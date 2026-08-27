"""Ölçümlü ve tamamen geri alınabilir düşük gecikme optimizasyonları.

Bu modül yalnızca iki dar kapsamlı çalışma zamanı ayarını değerlendirir:
kablosuz güç tasarrufu ve geri yüklenebilir basit FIFO qdisc'ler. DNS, rota,
MTU, IPv6, firewall ve kalıcı sysctl ayarlarına bilerek dokunmaz.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import json
import logging
import math
import os
import re
import socket
import statistics
import time
from dataclasses import asdict, dataclass, field
from typing import Callable, Sequence

from .constants import LATENCY_STATE_FILE
from .netmon import NetworkFingerprint
from .util import mark_socket, run, which

log = logging.getLogger("dpibypass.latency")

_IFACE_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,15}\Z")
_PING_TIME_RE = re.compile(r"time[=<]([0-9]+(?:\.[0-9]+)?)\s*ms", re.I)
_VIRTUAL_PREFIXES = (
    "lo", "docker", "veth", "virbr", "br-", "cni", "flannel", "podman",
    "tun", "tap", "wg", "tailscale", "zt", "dummy", "ifb", "bond",
)
_REMOTE_TARGETS = (("1.1.1.1", 443), ("8.8.8.8", 443))

Runner = Callable[..., object]


class LatencyError(RuntimeError):
    pass


@dataclass
class LatencyStats:
    sent: int = 0
    received: int = 0
    median_ms: float | None = None
    minimum_ms: float | None = None
    p95_ms: float | None = None
    jitter_ms: float | None = None
    packet_loss: float = 100.0

    @classmethod
    def from_samples(cls, samples: Sequence[float], sent: int) -> "LatencyStats":
        values = [float(value) for value in samples if value >= 0]
        received = len(values)
        loss = 100.0 if sent <= 0 else max(0.0, (sent - received) * 100.0 / sent)
        if not values:
            return cls(sent=sent, received=0, packet_loss=round(loss, 2))
        ordered = sorted(values)
        p95_index = max(0, math.ceil(len(ordered) * 0.95) - 1)
        differences = [abs(values[i] - values[i - 1])
                       for i in range(1, len(values))]
        jitter = statistics.mean(differences) if differences else 0.0
        return cls(
            sent=sent,
            received=received,
            median_ms=round(float(statistics.median(values)), 2),
            minimum_ms=round(ordered[0], 2),
            p95_ms=round(ordered[p95_index], 2),
            jitter_ms=round(float(jitter), 2),
            packet_loss=round(loss, 2),
        )

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class LatencyMeasurement:
    method: str
    gateway: LatencyStats
    remote: LatencyStats
    targets: list[str] = field(default_factory=list)
    measured_at: float = field(default_factory=time.time)

    @property
    def connected(self) -> bool:
        return self.remote.received > 0

    def to_dict(self) -> dict:
        return {
            "method": self.method,
            "gateway": self.gateway.to_dict(),
            "remote": self.remote.to_dict(),
            "targets": list(self.targets),
            "measured_at": self.measured_at,
        }


@dataclass
class QdiscSnapshot:
    kind: str
    restore_args: list[str]
    applied_output: str = ""

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "restore_args": list(self.restore_args),
            "applied_output": self.applied_output,
        }


@dataclass
class LatencySnapshot:
    interface: str
    link_type: str
    wifi_power_save: str | None = None
    qdisc: QdiscSnapshot | None = None

    def to_dict(self) -> dict:
        return {
            "interface": self.interface,
            "link_type": self.link_type,
            "wifi_power_save": self.wifi_power_save,
            "qdisc": self.qdisc.to_dict() if self.qdisc else None,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "LatencySnapshot":
        iface = data.get("interface")
        link_type = data.get("link_type")
        if not isinstance(iface, str) or not _IFACE_RE.match(iface):
            raise ValueError("geçersiz latency snapshot arayüzü")
        if link_type not in ("wifi", "ethernet", "mobile"):
            raise ValueError("geçersiz latency snapshot bağlantı türü")
        power = data.get("wifi_power_save")
        if power not in (None, "on", "off"):
            raise ValueError("geçersiz Wi-Fi güç tasarrufu snapshot'ı")
        qdisc_data = data.get("qdisc")
        qdisc = None
        if qdisc_data is not None:
            if not isinstance(qdisc_data, dict):
                raise ValueError("geçersiz qdisc snapshot'ı")
            kind = qdisc_data.get("kind")
            args = qdisc_data.get("restore_args")
            applied_output = qdisc_data.get("applied_output", "")
            if kind not in ("pfifo", "bfifo", "pfifo_fast") or not isinstance(args, list):
                raise ValueError("güvenli olmayan qdisc snapshot'ı")
            if not all(isinstance(item, str) and item for item in args):
                raise ValueError("geçersiz qdisc geri alma argümanı")
            if (not isinstance(applied_output, str) or
                    (applied_output and not applied_output.startswith(
                        "qdisc fq_codel ")) or len(applied_output) > 4096):
                raise ValueError("geçersiz uygulanmış qdisc imzası")
            qdisc = QdiscSnapshot(
                kind=kind, restore_args=list(args),
                applied_output=applied_output)
        return cls(interface=iface, link_type=link_type,
                   wifi_power_save=power, qdisc=qdisc)


@dataclass
class LatencyStatus:
    enabled: bool = False
    active: bool = False
    interface: str = ""
    state: str = "disabled"
    message: str = "Kapalı"
    before: LatencyMeasurement | None = None
    after: LatencyMeasurement | None = None
    applied: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "enabled": self.enabled,
            "active": self.active,
            "interface": self.interface,
            "state": self.state,
            "message": self.message,
            "before": self.before.to_dict() if self.before else None,
            "after": self.after.to_dict() if self.after else None,
            "applied": list(self.applied),
            "skipped": list(self.skipped),
        }


class LatencyProbe:
    """DNS kullanmadan ICMP, gerekirse TCP-connect örnekleri toplar."""

    def __init__(self, runner: Runner = run,
                 which_fn: Callable[[str], str | None] = which,
                 samples: int = 5, deadline: int = 5) -> None:
        self.runner = runner
        self.which = which_fn
        self.samples = max(3, int(samples))
        self.deadline = max(2, int(deadline))

    def _ping(self, target: str, interface: str) -> tuple[list[float], int]:
        cmd = ["ping", "-n", "-c", str(self.samples), "-i", "0.2",
               "-W", "1", "-w", str(self.deadline)]
        if interface:
            cmd.extend(["-I", interface])
        cmd.append(target)
        result = self.runner(cmd, timeout=self.deadline + 2)
        output = str(getattr(result, "stdout", "") or "")
        values = [float(match.group(1)) for match in _PING_TIME_RE.finditer(output)]
        return values, self.samples

    @staticmethod
    def _tcp(target: str, port: int, samples: int) -> tuple[list[float], int]:
        values: list[float] = []
        for _index in range(samples):
            started = time.perf_counter()
            sock = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.2)
                # Daemon'ın kendi ölçümü "all" kipindeki şeffaf yönlendirmeye
                # düşmemeli; aksi halde yalnız yerel proxy connect süresi
                # ölçülürdü. Hedef IP doğrudan, DNS kullanılmadan bağlanır.
                mark_socket(sock)
                sock.connect((target, port))
            except OSError:
                continue
            else:
                values.append((time.perf_counter() - started) * 1000.0)
            finally:
                if sock is not None:
                    sock.close()
        return values, samples

    def measure(self, interface: str, gateway: str) -> LatencyMeasurement:
        ping_available = self.which("ping") is not None
        gateway_values: list[float] = []
        gateway_sent = 0
        remote_values: list[float] = []
        remote_groups: list[list[float]] = []
        remote_sent = 0
        targets = [target for target, _port in _REMOTE_TARGETS]

        if ping_available:
            jobs: list[tuple[str, concurrent.futures.Future]] = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
                if gateway:
                    jobs.append(("gateway", pool.submit(
                        self._ping, gateway, interface)))
                for target, _port in _REMOTE_TARGETS:
                    jobs.append(("remote", pool.submit(
                        self._ping, target, interface)))
                for kind, future in jobs:
                    try:
                        values, sent = future.result()
                    except Exception as exc:
                        log.debug("gecikme ping örneği alınamadı: %s", exc)
                        continue
                    if kind == "gateway":
                        gateway_values.extend(values)
                        gateway_sent += sent
                    else:
                        remote_values.extend(values)
                        if values:
                            remote_groups.append(values)
                        remote_sent += sent

        method = "icmp"
        # Uzak ICMP örneklerinin çoğu kayıpsa endpoint rate-limit'i sonucu
        # yanıltabilir; bu durumda ölçüm türünü tamamen TCP'ye çevir.
        if (not remote_values or
                (remote_sent and len(remote_values) < remote_sent * 0.6)):
            method = "tcp-connect"
            remote_values = []
            remote_groups = []
            remote_sent = 0
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(self._tcp, target, port, self.samples)
                           for target, port in _REMOTE_TARGETS]
                for future in futures:
                    try:
                        values, sent = future.result()
                    except Exception as exc:
                        log.debug("TCP gecikme örneği alınamadı: %s", exc)
                        continue
                    remote_values.extend(values)
                    if values:
                        remote_groups.append(values)
                    remote_sent += sent

        remote_stats = LatencyStats.from_samples(remote_values, remote_sent)
        # Farklı uzak hedeflerin doğal RTT farkı jitter değildir. Ardışık farkı
        # her endpoint'in kendi örnek dizisinde hesaplayıp sonra birleştir.
        group_differences = [
            abs(values[index] - values[index - 1])
            for values in remote_groups for index in range(1, len(values))
        ]
        if remote_stats.received:
            remote_stats.jitter_ms = round(
                float(statistics.mean(group_differences))
                if group_differences else 0.0, 2)

        return LatencyMeasurement(
            method=method,
            gateway=LatencyStats.from_samples(gateway_values, gateway_sent),
            remote=remote_stats,
            targets=([gateway] if gateway else []) + targets,
        )


class LatencyOptimizer:
    """Ölç → uygula → yeniden ölç → doğrula/geri al düzenleyicisi."""

    def __init__(self, runner: Runner = run,
                 which_fn: Callable[[str], str | None] = which,
                 probe: LatencyProbe | None = None,
                 state_path: str = LATENCY_STATE_FILE) -> None:
        self.runner = runner
        self.which = which_fn
        self.probe = probe or LatencyProbe(runner, which_fn)
        self.state_path = state_path
        self.status = LatencyStatus()
        self.snapshot: LatencySnapshot | None = None
        self._lock: asyncio.Lock | None = None
        self._generation = 0

    def _get_lock(self) -> asyncio.Lock:
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    def request_cancel(self) -> None:
        """Devam eden ölçümü güvenli aşama sınırında durdur."""
        self._generation += 1

    def status_dict(self) -> dict:
        return self.status.to_dict()

    @staticmethod
    def _safe_network(network: NetworkFingerprint) -> tuple[bool, str]:
        iface = network.interface
        if not iface or not _IFACE_RE.match(iface):
            return False, "Geçerli bir aktif ağ arayüzü bulunamadı"
        lowered = iface.lower()
        if network.link_type == "vpn" or lowered.startswith(_VIRTUAL_PREFIXES):
            return False, "VPN veya sanal ağ arayüzlerine dokunulmaz"
        if network.link_type not in ("wifi", "ethernet", "mobile"):
            return False, "Bu arayüz türü güvenli optimizasyon için desteklenmiyor"
        if not network.is_online():
            return False, "Ağ bağlantısı yok"
        return True, ""

    async def _blocking(self, func: Callable, *args, **kwargs):
        loop = asyncio.get_running_loop()
        # Bazı eski Python/libc birleşimlerinde varsayılan executor'ın yeniden
        # kullanılan worker'ı kapanış sırasında takılabiliyor. Kısa ömürlü,
        # tek işlik executor hem Python 3.8 uyumlu hem de daemon kapanışını
        # öngörülebilir tutar.
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        try:
            return await loop.run_in_executor(
                executor, lambda: func(*args, **kwargs))
        finally:
            executor.shutdown(wait=False)

    async def _command(self, cmd: list[str], timeout: int = 8):
        return await self._blocking(self.runner, cmd, timeout=timeout)

    async def _measure(self, network: NetworkFingerprint) -> LatencyMeasurement:
        return await self._blocking(
            self.probe.measure, network.interface, network.gateway)

    async def recover(self) -> bool:
        """Önceki servis sürecinden kalan runtime ayarlarını geri al."""
        async with self._get_lock():
            stale = self._load_snapshot()
            if stale is None:
                return True
            log.warning("Önceki gecikme ayarları bulundu; geri alınıyor (%s)",
                        stale.interface)
            ok = await self._restore(stale)
            if ok:
                self._drop_snapshot()
                self.snapshot = None
            else:
                self.snapshot = stale
                self.status = LatencyStatus(
                    enabled=False, active=True, interface=stale.interface,
                    state="rollback-failed",
                    message="Önceki gecikme ayarları geri alınamadı",
                )
            return ok

    async def optimize(self, network: NetworkFingerprint) -> dict:
        async with self._get_lock():
            generation = self._generation
            safe, reason = self._safe_network(network)
            self.status = LatencyStatus(
                enabled=True, interface=network.interface,
                state="measuring" if safe else "unsupported",
                message="Başlangıç gecikmesi ölçülüyor…" if safe else reason,
            )
            if not safe:
                return self.status_dict()

            try:
                before = await self._measure(network)
                self.status.before = before
                if self._cancelled(generation):
                    return self._cancel_status(network.interface, before)
                if not before.connected:
                    self.status.state = "failed"
                    self.status.message = "Bağlantı testi başarısız; hiçbir ayar değiştirilmedi"
                    return self.status_dict()

                self.status.state = "applying"
                self.status.message = "Desteklenen güvenli ayarlar değerlendiriliyor…"
                snapshot, planned, skipped = await self._plan(network)
                self.status.skipped = skipped
                if self._cancelled(generation):
                    return self._cancel_status(network.interface, before)
                if not planned:
                    already = any("zaten" in item for item in skipped)
                    self.status.state = "already-optimal" if already else "unsupported"
                    self.status.message = (
                        "Desteklenen düşük gecikme ayarları zaten etkin"
                        if already else
                        "Bu ağda desteklenen güvenli optimizasyon bulunamadı"
                    )
                    return self.status_dict()

                self.snapshot = snapshot
                self._save_snapshot(snapshot)
                applied = await self._apply(snapshot, planned)
                self.status.applied = applied
                if self._cancelled(generation):
                    await self._rollback("Ağ değişti; eski ayarlar geri alındı")
                    return self.status_dict()

                self.status.state = "verifying"
                self.status.message = "Değişiklik sonrası gecikme ölçülüyor…"
                after = await self._measure(network)
                self.status.after = after
                if self._cancelled(generation):
                    await self._rollback("Ağ değişti; eski ayarlar geri alındı")
                    return self.status_dict()

                verified, verdict = self.evaluate(before, after)
                if not verified:
                    await self._rollback(verdict)
                    return self.status_dict()

                self.status.state = "active"
                self.status.active = True
                self.status.message = self._gain_message(before, after)
                log.info("Ping düşürme doğrulandı: %s", self.status.message)
                return self.status_dict()
            except LatencyError as exc:
                log.warning("Ping düşürme uygulanamadı: %s", exc)
                if self.snapshot is not None:
                    await self._rollback(
                        f"Optimizasyon hatası; ayarlar geri alındı: {exc}")
                else:
                    self.status.state = "failed"
                    self.status.message = f"Optimizasyon uygulanamadı: {exc}"
                return self.status_dict()
            except Exception as exc:
                log.exception("Ping düşürme akışı hata verdi")
                if self.snapshot is not None:
                    await self._rollback(
                        f"Optimizasyon hatası; ayarlar geri alındı: {exc}")
                else:
                    self.status.state = "failed"
                    self.status.message = f"Optimizasyon uygulanamadı: {exc}"
                return self.status_dict()

    async def disable(self) -> bool:
        self.request_cancel()
        async with self._get_lock():
            snapshot = self.snapshot or self._load_snapshot()
            ok = True
            if snapshot is not None:
                ok = await self._restore(snapshot)
                if ok:
                    self._drop_snapshot()
                    self.snapshot = None
            self.status = LatencyStatus(
                enabled=False,
                active=False if ok else True,
                interface=snapshot.interface if snapshot else self.status.interface,
                state="disabled" if ok else "rollback-failed",
                message="Kapalı; tüm değişiklikler geri alındı" if ok else
                        "Bazı ayarlar geri alınamadı; servis günlüğünü kontrol edin",
            )
            return ok

    async def measure_only(self, network: NetworkFingerprint) -> LatencyMeasurement:
        async with self._get_lock():
            safe, reason = self._safe_network(network)
            if not safe:
                raise LatencyError(reason)
            measurement = await self._measure(network)
            if not measurement.connected:
                raise LatencyError("Uzak hedeflere bağlantı ölçülemedi")
            if not self.status.enabled:
                self.status.interface = network.interface
                self.status.state = "measured"
                self.status.message = self._measurement_message(measurement)
            return measurement

    async def _plan(self, network: NetworkFingerprint) -> tuple[
            LatencySnapshot, list[str], list[str]]:
        snapshot = LatencySnapshot(network.interface, network.link_type)
        planned: list[str] = []
        skipped: list[str] = []

        if network.link_type == "wifi":
            if self.which("iw") is None:
                skipped.append("iw bulunamadı; Wi-Fi güç tasarrufu atlandı")
            else:
                result = await self._command(
                    ["iw", "dev", network.interface, "get", "power_save"])
                match = re.search(r"Power save:\s*(on|off)",
                                  str(getattr(result, "stdout", "") or ""), re.I)
                if getattr(result, "returncode", 1) != 0 or match is None:
                    skipped.append("Sürücü Wi-Fi güç tasarrufu sorgusunu desteklemiyor")
                elif match.group(1).lower() == "off":
                    skipped.append("Wi-Fi güç tasarrufu zaten kapalı")
                else:
                    snapshot.wifi_power_save = "on"
                    planned.append("wifi-power-save")
        else:
            skipped.append("Arayüz Wi-Fi değil; güç tasarrufu değişmedi")

        if self.which("tc") is None:
            skipped.append("tc bulunamadı; kuyruk disiplini atlandı")
        else:
            result = await self._command(
                ["tc", "qdisc", "show", "dev", network.interface])
            if getattr(result, "returncode", 1) != 0:
                skipped.append("Kuyruk disiplini güvenle okunamadı")
            else:
                qdisc, note = self._qdisc_candidate(
                    str(getattr(result, "stdout", "") or ""))
                if qdisc is None:
                    skipped.append(note)
                else:
                    snapshot.qdisc = qdisc
                    planned.append("fq_codel")
        return snapshot, planned, skipped

    @staticmethod
    def _qdisc_candidate(output: str) -> tuple[QdiscSnapshot | None, str]:
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        if len(lines) != 1:
            return None, "Custom veya çok katmanlı qdisc korundu"
        match = re.match(r"^qdisc\s+(\S+)\s+(\S+)\s+root(?:\s+refcnt\s+\d+)?(?:\s+(.*))?$",
                         lines[0])
        if match is None:
            return None, "Qdisc yapısı kesin olarak tanınmadı; korundu"
        kind, handle, options = match.groups()
        if kind == "cake":
            return None, "cake zaten etkin; değiştirilmedi"
        if kind == "fq_codel":
            return None, "fq_codel zaten etkin; değiştirilmedi"
        if kind == "fq":
            return None, "fq qdisc körü körüne değiştirilmedi"
        if kind in ("mq", "noqueue"):
            return None, f"{kind} qdisc yapısı korundu"
        if kind not in ("pfifo", "bfifo", "pfifo_fast"):
            return None, f"Custom qdisc ({kind}) korundu"

        tokens = options.split() if options else []
        if kind in ("pfifo", "bfifo"):
            if len(tokens) != 2 or tokens[0] != "limit" or not re.match(
                    r"^[0-9]+[pb]?\Z", tokens[1]):
                return None, f"Özel {kind} seçenekleri kesin geri alınamıyor; korundu"
        elif tokens:
            if len(tokens) < 3 or tokens[0] != "bands" or "priomap" not in tokens:
                return None, "Özel pfifo_fast yapısı kesin geri alınamıyor; korundu"
            if not all(re.match(r"^[A-Za-z0-9_.:-]+\Z", token) for token in tokens):
                return None, "pfifo_fast seçenekleri güvenli ayrıştırılamadı; korundu"

        restore = []
        if handle != "0:":
            restore.extend(["handle", handle])
        restore.append(kind)
        restore.extend(tokens)
        return QdiscSnapshot(kind=kind, restore_args=restore), ""

    async def _apply(self, snapshot: LatencySnapshot,
                     planned: list[str]) -> list[str]:
        applied: list[str] = []
        iface = snapshot.interface
        if "wifi-power-save" in planned:
            result = await self._command(
                ["iw", "dev", iface, "set", "power_save", "off"])
            if getattr(result, "returncode", 1) != 0:
                raise LatencyError("Wi-Fi güç tasarrufu kapatılamadı")
            applied.append("Wi-Fi güç tasarrufu kapatıldı")
        if "fq_codel" in planned:
            result = await self._command(
                ["tc", "qdisc", "replace", "dev", iface, "root", "fq_codel"])
            if getattr(result, "returncode", 1) != 0:
                raise LatencyError("fq_codel uygulanamadı")
            current = await self._command(
                ["tc", "qdisc", "show", "dev", iface])
            output = self._normalize_qdisc(
                str(getattr(current, "stdout", "") or ""))
            if (getattr(current, "returncode", 1) != 0 or
                    not output.startswith("qdisc fq_codel ") or "\n" in output):
                raise LatencyError("uygulanan fq_codel doğrulanamadı")
            if snapshot.qdisc is None:  # plan ile garanti edilir; savunmacı kontrol
                raise LatencyError("qdisc snapshot'ı kayboldu")
            snapshot.qdisc.applied_output = output
            # Crash cleanup yolu yalnız bizim kurduğumuz qdisc'i geri alsın.
            self._save_snapshot(snapshot)
            applied.append("fq_codel uygulandı")
        return applied

    async def _rollback(self, message: str) -> bool:
        snapshot = self.snapshot or self._load_snapshot()
        ok = True if snapshot is None else await self._restore(snapshot)
        if ok:
            self._drop_snapshot()
            self.snapshot = None
        self.status.active = not ok
        self.status.applied = [] if ok else self.status.applied
        self.status.state = "rolled-back" if ok else "rollback-failed"
        self.status.message = message if ok else (
            "Ayarların tamamı geri alınamadı; servis günlüğünü kontrol edin")
        log.info("Ping düşürme sonucu: %s", self.status.message)
        return ok

    async def _restore(self, snapshot: LatencySnapshot) -> bool:
        ok = True
        iface = snapshot.interface
        # Uygulama sırasının tersi: önce qdisc, sonra Wi-Fi.
        if snapshot.qdisc is not None:
            if self.which("tc") is None:
                log.error("qdisc geri alınamadı: tc bulunamadı")
                ok = False
            else:
                should_restore = True
                if snapshot.qdisc.applied_output:
                    current = await self._command(
                        ["tc", "qdisc", "show", "dev", iface])
                    if getattr(current, "returncode", 1) != 0:
                        log.error("%s güncel qdisc okunamadı", iface)
                        should_restore = False
                        ok = False
                    elif self._normalize_qdisc(
                            str(getattr(current, "stdout", "") or "")) != \
                            snapshot.qdisc.applied_output:
                        log.warning("%s qdisc dışarıdan değiştirildi; "
                                    "custom yapı korunuyor", iface)
                        should_restore = False
                if should_restore:
                    cmd = (["tc", "qdisc", "replace", "dev", iface, "root"]
                           + snapshot.qdisc.restore_args)
                    result = await self._command(cmd)
                    if getattr(result, "returncode", 1) != 0:
                        log.error("%s qdisc geri alınamadı", iface)
                        ok = False
        if snapshot.wifi_power_save is not None:
            if self.which("iw") is None:
                log.error("Wi-Fi güç tasarrufu geri alınamadı: iw bulunamadı")
                ok = False
            else:
                result = await self._command(
                    ["iw", "dev", iface, "set", "power_save",
                     snapshot.wifi_power_save])
                if getattr(result, "returncode", 1) != 0:
                    log.error("%s Wi-Fi güç tasarrufu geri alınamadı", iface)
                    ok = False
        return ok

    def restore_persisted_sync(self) -> bool:
        """``dpi-bypassd --cleanup`` için olay döngüsüz geri alma yolu."""
        snapshot = self._load_snapshot()
        if snapshot is None:
            return True
        ok = True
        if snapshot.qdisc is not None:
            should_restore = True
            if snapshot.qdisc.applied_output:
                current = self.runner(
                    ["tc", "qdisc", "show", "dev", snapshot.interface],
                    timeout=8)
                if getattr(current, "returncode", 1) != 0:
                    should_restore = False
                    ok = False
                elif self._normalize_qdisc(
                        str(getattr(current, "stdout", "") or "")) != \
                        snapshot.qdisc.applied_output:
                    log.warning("%s qdisc dışarıdan değiştirildi; custom yapı "
                                "korunuyor", snapshot.interface)
                    should_restore = False
            if should_restore:
                result = self.runner(
                    ["tc", "qdisc", "replace", "dev", snapshot.interface,
                     "root"] + snapshot.qdisc.restore_args, timeout=8)
                ok = getattr(result, "returncode", 1) == 0 and ok
        if snapshot.wifi_power_save is not None:
            result = self.runner(
                ["iw", "dev", snapshot.interface, "set", "power_save",
                 snapshot.wifi_power_save], timeout=8)
            ok = getattr(result, "returncode", 1) == 0 and ok
        if ok:
            self._drop_snapshot()
        return ok

    @staticmethod
    def _normalize_qdisc(output: str) -> str:
        return "\n".join(line.strip() for line in output.splitlines()
                         if line.strip())

    def _save_snapshot(self, snapshot: LatencySnapshot) -> None:
        directory = os.path.dirname(self.state_path)
        os.makedirs(directory, mode=0o755, exist_ok=True)
        tmp = self.state_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(snapshot.to_dict(), handle, ensure_ascii=False)
            handle.write("\n")
        os.replace(tmp, self.state_path)

    def _load_snapshot(self) -> LatencySnapshot | None:
        try:
            with open(self.state_path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            if not isinstance(data, dict):
                raise ValueError("snapshot nesne değil")
            return LatencySnapshot.from_dict(data)
        except FileNotFoundError:
            return None
        except (OSError, ValueError) as exc:
            log.error("Gecikme geri alma durumu okunamadı: %s", exc)
            return None

    def _drop_snapshot(self) -> None:
        try:
            os.unlink(self.state_path)
        except OSError:
            pass

    def _cancelled(self, generation: int) -> bool:
        return generation != self._generation

    def _cancel_status(self, interface: str,
                       before: LatencyMeasurement) -> dict:
        self.status = LatencyStatus(
            enabled=self.status.enabled, interface=interface,
            state="cancelled", message="Ölçüm ağ değişikliği nedeniyle iptal edildi",
            before=before,
        )
        return self.status_dict()

    @staticmethod
    def evaluate(before: LatencyMeasurement,
                 after: LatencyMeasurement) -> tuple[bool, str]:
        if not after.connected:
            return False, "Bağlantı testi başarısız; ayarlar geri alındı"
        if before.method != after.method:
            return False, ("Ölçüm yöntemi değişti; sonuçlar karşılaştırılamadı ve "
                           "ayarlar geri alındı")
        old, new = before.remote, after.remote
        if new.packet_loss > old.packet_loss + 0.01:
            return False, "Paket kaybı arttı; ayarlar geri alındı"
        if old.median_ms is None or new.median_ms is None:
            return False, "Gecikme doğrulanamadı; ayarlar geri alındı"

        median_worse = new.median_ms - old.median_ms > max(2.0, old.median_ms * 0.10)
        p95_worse = (old.p95_ms is not None and new.p95_ms is not None and
                     new.p95_ms - old.p95_ms > max(3.0, old.p95_ms * 0.15))
        jitter_worse = (old.jitter_ms is not None and new.jitter_ms is not None and
                        new.jitter_ms - old.jitter_ms > max(2.0, old.jitter_ms * 0.25))
        if median_worse or p95_worse or jitter_worse:
            return False, "RTT veya jitter kötüleşti; ayarlar geri alındı"

        median_gain = old.median_ms - new.median_ms >= max(2.0, old.median_ms * 0.05)
        p95_gain = (old.p95_ms is not None and new.p95_ms is not None and
                    old.p95_ms - new.p95_ms >= max(3.0, old.p95_ms * 0.08))
        jitter_gain = (old.jitter_ms is not None and new.jitter_ms is not None and
                       old.jitter_ms - new.jitter_ms >= max(1.5, old.jitter_ms * 0.20))
        if median_gain or p95_gain or jitter_gain:
            return True, "doğrulandı"
        return False, ("Bu ağda doğrulanmış bir gecikme kazancı bulunamadı; "
                       "gereksiz değişiklikler geri alındı")

    @staticmethod
    def _gain_message(before: LatencyMeasurement,
                      after: LatencyMeasurement) -> str:
        old, new = before.remote, after.remote
        return (f"Doğrulandı: {old.median_ms:g} ms → {new.median_ms:g} ms · "
                f"jitter {old.jitter_ms:g} ms → {new.jitter_ms:g} ms")

    @staticmethod
    def _measurement_message(measurement: LatencyMeasurement) -> str:
        remote = measurement.remote
        return (f"{remote.median_ms:g} ms median · {remote.p95_ms:g} ms p95 · "
                f"{remote.jitter_ms:g} ms jitter · %{remote.packet_loss:g} kayıp")
