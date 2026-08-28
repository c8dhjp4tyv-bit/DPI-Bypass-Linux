"""Aday tabanlı, ölçümlü ve tamamen geri alınabilir düşük gecikme motoru.

Tasarım
-------
Tek bir ayarı uygulayıp "ping düştü" demek yerine motor şunu yapar::

    taban ölçüm
      → aday A uygula → ölç → geri al
      → aday B uygula → ölç → geri al
      → ...
      → istatistiksel olarak anlamlı kazancı olan en iyi adayı seç
      → uygula → son doğrulama → kazanç yoksa geri al

Adaylar donanıma ve bağlantı türüne göre üretilir. Yalnızca bu sistemde
teknik olarak anlamı olan, okunabilir ve geri yüklenebilir çalışma zamanı
ayarları aday olur:

* Wi-Fi güç tasarrufu (``iw dev … set power_save off``) — uyku/uyanma
  gecikmesini kaldırır, kablosuzda ölçülebilir en büyük etkilerden biri.
* Kök qdisc'in ``fq_codel`` / ``fq`` / ``cake`` ile değiştirilmesi — yalnızca
  mevcut qdisc *kesin geri yüklenebilir basit bir FIFO* ise. Kullanıcının ya
  da başka bir programın kurduğu qdisc asla ezilmez.
* Ethernet'te Energy Efficient Ethernet (``ethtool --set-eee … eee off``) —
  LPI uyanma gecikmesini kaldırır; sürücü desteklemiyorsa sessizce atlanır.
* Ethernet'te RX interrupt coalescing (``ethtool -C … adaptive-rx off
  rx-usecs 0``) — kesme gecikmesini düşürür; desteklenmiyorsa atlanır.

Bilerek **yapılmayanlar**: DNS değiştirme, rota/MTU/IPv6 oynaması, kalıcı
sysctl yazımı, TCP tıkanıklık denetimi (BBR) seçimi, güvenlik duvarı kuralı.
Bunların hiçbiri bir oyunun UDP RTT'sini düşürmez; bir kısmı bağlantıyı
bozar. "Popüler" olmaları aday olmaları için yeterli değil.

Ölçüm
-----
Her ölçüm noktası; ısınma turu + birden çok ölçüm turu içerir ve minimum,
median, p95, jitter, paket kaybı ile ağ geçidi/uzak RTT'yi ayrı ayrı
raporlar. Gürültü seviyesindeki farklar (20.1 ms → 19.8 ms) kazanç sayılmaz;
eşikler median, p95 ve jitter için ayrı ayrı tanımlıdır.

``spread_ms`` (p95 − min) gözlenen gecikme yayılımının göstergesidir. Gerçek
bufferbloat ölçümü bağlantıyı doyurmayı gerektirir; kullanıcının hattını
kasten doldurmak bu aracın işi değildir, bu yüzden doygunluk testi yapılmaz
ve yapılmış gibi de gösterilmez.
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

from .constants import LATENCY_PROFILE_FILE, LATENCY_STATE_FILE
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

#: Geri yüklenebilirliği kesin olan qdisc türleri. Bunların dışındaki her şey
#: (htb, cake, fq_codel, mq, noqueue, custom hiyerarşiler) korunur.
_REPLACEABLE_QDISCS = ("pfifo", "bfifo", "pfifo_fast")
#: Aday olarak denenebilecek qdisc türleri.
_QDISC_TARGETS = ("fq_codel", "fq", "cake")

#: ethtool -C ile hem okunup hem yazılabilen, gecikmeyle doğrudan ilgili
#: parametreler. Listeyi dar tutmak, geri almayı da kesinleştirir.
_COALESCE_KEYS = ("adaptive-rx", "rx-usecs", "rx-frames")
_COALESCE_VALUE_RE = re.compile(r"^(?:on|off|[0-9]{1,9})\Z")

Runner = Callable[..., object]


class LatencyError(RuntimeError):
    pass


# --------------------------------------------------------------------------- #
# ölçüm veri yapıları
# --------------------------------------------------------------------------- #
@dataclass
class LatencyStats:
    sent: int = 0
    received: int = 0
    median_ms: float | None = None
    minimum_ms: float | None = None
    p95_ms: float | None = None
    jitter_ms: float | None = None
    #: p95 − min. Gözlenen gecikme yayılımı; doygunluk (bufferbloat) testi
    #: DEĞİLDİR, yalnızca mevcut trafik altındaki kuyruk göstergesidir.
    spread_ms: float | None = None
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
            spread_ms=round(ordered[p95_index] - ordered[0], 2),
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
    rounds: int = 1

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
            "rounds": self.rounds,
        }


# --------------------------------------------------------------------------- #
# geri alma tarifleri
# --------------------------------------------------------------------------- #
@dataclass
class ActionSnapshot:
    """Tek bir çalışma zamanı değişikliğinin eksiksiz geri alma tarifi.

    ``signature`` uygulamadan **sonra** okunan durumdur; geri alırken sistem
    hâlâ o durumdaysa bizim değişikliğimiz duruyor demektir. Farklıysa
    kullanıcı ya da başka bir program araya girmiştir ve ayarı ezmeyiz.
    """

    kind: str
    interface: str
    restore: dict = field(default_factory=dict)
    signature: str = ""
    label: str = ""

    def to_dict(self) -> dict:
        return {"kind": self.kind, "interface": self.interface,
                "restore": dict(self.restore), "signature": self.signature,
                "label": self.label}

    @classmethod
    def from_dict(cls, data: dict) -> "ActionSnapshot":
        if not isinstance(data, dict):
            raise ValueError("geçersiz eylem snapshot'ı")
        kind = data.get("kind")
        iface = data.get("interface")
        restore = data.get("restore")
        signature = data.get("signature", "")
        label = data.get("label", "")
        if not isinstance(iface, str) or not _IFACE_RE.match(iface):
            raise ValueError("geçersiz snapshot arayüzü")
        if not isinstance(restore, dict):
            raise ValueError("geçersiz geri alma tarifi")
        if not isinstance(signature, str) or len(signature) > 4096:
            raise ValueError("geçersiz uygulanmış durum imzası")
        if not isinstance(label, str) or len(label) > 200:
            raise ValueError("geçersiz eylem etiketi")

        if kind == "wifi-power-save":
            if restore.get("value") not in ("on", "off"):
                raise ValueError("geçersiz Wi-Fi güç tasarrufu snapshot'ı")
        elif kind == "eee":
            if restore.get("value") not in ("on", "off"):
                raise ValueError("geçersiz EEE snapshot'ı")
        elif kind == "coalesce":
            params = restore.get("params")
            if not isinstance(params, dict) or not params:
                raise ValueError("geçersiz coalesce snapshot'ı")
            for key, value in params.items():
                if key not in _COALESCE_KEYS or not isinstance(value, str) \
                        or not _COALESCE_VALUE_RE.match(value):
                    raise ValueError("güvenli olmayan coalesce parametresi")
        elif kind == "qdisc":
            base = restore.get("kind")
            args = restore.get("args")
            if base not in _REPLACEABLE_QDISCS or not isinstance(args, list):
                raise ValueError("güvenli olmayan qdisc snapshot'ı")
            if not all(isinstance(item, str) and item and
                       re.match(r"^[A-Za-z0-9_.:+-]+\Z", item) for item in args):
                raise ValueError("geçersiz qdisc geri alma argümanı")
            if signature and not re.match(
                    r"^qdisc (?:%s) " % "|".join(_QDISC_TARGETS), signature):
                raise ValueError("geçersiz uygulanmış qdisc imzası")
            if "\n" in signature:
                raise ValueError("çok katmanlı qdisc imzası")
        else:
            raise ValueError(f"bilinmeyen eylem türü: {kind!r}")
        return cls(kind=kind, interface=iface, restore=dict(restore),
                   signature=signature, label=label)


@dataclass
class LatencySnapshot:
    """Bir arayüzde uygulanmış bütün eylemlerin sırayla geri alma tarifi."""

    interface: str
    link_type: str
    actions: list[ActionSnapshot] = field(default_factory=list)
    candidate: str = ""

    def to_dict(self) -> dict:
        return {
            "interface": self.interface,
            "link_type": self.link_type,
            "candidate": self.candidate,
            "actions": [action.to_dict() for action in self.actions],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "LatencySnapshot":
        iface = data.get("interface")
        link_type = data.get("link_type")
        if not isinstance(iface, str) or not _IFACE_RE.match(iface):
            raise ValueError("geçersiz latency snapshot arayüzü")
        if link_type not in ("wifi", "ethernet", "mobile"):
            raise ValueError("geçersiz latency snapshot bağlantı türü")
        candidate = data.get("candidate", "")
        if not isinstance(candidate, str) or len(candidate) > 120:
            raise ValueError("geçersiz aday adı")
        raw_actions = data.get("actions")
        if raw_actions is None:
            # 1.2.0 biçimi: tek Wi-Fi + tek qdisc alanı. Servis yükseltmesinden
            # hemen sonra /run altında kalmış olabilir; geri alınabilmeli.
            return cls(interface=iface, link_type=link_type,
                       actions=_legacy_actions(data, iface),
                       candidate=candidate)
        if not isinstance(raw_actions, list):
            raise ValueError("geçersiz eylem listesi")
        actions = [ActionSnapshot.from_dict(item) for item in raw_actions]
        if any(action.interface != iface for action in actions):
            raise ValueError("snapshot arayüzleri tutarsız")
        return cls(interface=iface, link_type=link_type, actions=actions,
                   candidate=candidate)


def _legacy_actions(data: dict, iface: str) -> list[ActionSnapshot]:
    """Eski (tek eylemli) snapshot biçimini yeni eylem listesine çevirir."""
    actions: list[ActionSnapshot] = []
    qdisc = data.get("qdisc")
    if qdisc is not None:
        if not isinstance(qdisc, dict):
            raise ValueError("geçersiz qdisc snapshot'ı")
        actions.append(ActionSnapshot.from_dict({
            "kind": "qdisc", "interface": iface,
            "restore": {"kind": qdisc.get("kind"),
                        "args": qdisc.get("restore_args")},
            "signature": qdisc.get("applied_output", ""),
            "label": "fq_codel",
        }))
    power = data.get("wifi_power_save")
    if power is not None:
        if power not in ("on", "off"):
            raise ValueError("geçersiz Wi-Fi güç tasarrufu snapshot'ı")
        actions.append(ActionSnapshot.from_dict({
            "kind": "wifi-power-save", "interface": iface,
            "restore": {"value": power}, "signature": "",
            "label": "Wi-Fi güç tasarrufu",
        }))
    return actions


# --------------------------------------------------------------------------- #
# adaylar
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Step:
    """Bir adayın tek bir adımı — henüz uygulanmamış niyet."""

    kind: str
    target: str = ""
    label: str = ""

    def to_dict(self) -> dict:
        return {"kind": self.kind, "target": self.target, "label": self.label}


@dataclass(frozen=True)
class Candidate:
    key: str
    label: str
    steps: tuple[Step, ...]

    def to_dict(self) -> dict:
        return {"key": self.key, "label": self.label,
                "steps": [step.to_dict() for step in self.steps]}


@dataclass
class CandidateResult:
    key: str
    label: str
    applied: list[str] = field(default_factory=list)
    measurement: LatencyMeasurement | None = None
    score: float | None = None
    verified: bool = False
    verdict: str = ""

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "label": self.label,
            "applied": list(self.applied),
            "measurement": self.measurement.to_dict() if self.measurement else None,
            "score": None if self.score is None else round(self.score, 2),
            "verified": self.verified,
            "verdict": self.verdict,
        }


@dataclass
class Environment:
    """Arayüzün ölçüm öncesi okunmuş gerçek durumu."""

    interface: str
    link_type: str
    wifi_power_save: str | None = None          # "on" | "off" | None
    qdisc_kind: str = ""
    qdisc_restore: list[str] = field(default_factory=list)
    qdisc_replaceable: bool = False
    qdisc_targets: tuple[str, ...] = ()
    eee: str | None = None                      # "enabled" | "disabled" | None
    coalesce: dict[str, str] = field(default_factory=dict)
    coalesce_worth_trying: bool = False
    notes: list[str] = field(default_factory=list)


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
    candidates: list[CandidateResult] = field(default_factory=list)
    best: str = ""
    cached: bool = False
    gain: dict = field(default_factory=dict)

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
            "candidates": [item.to_dict() for item in self.candidates],
            "best": self.best,
            "cached": self.cached,
            "gain": dict(self.gain),
        }


# --------------------------------------------------------------------------- #
# ölçüm
# --------------------------------------------------------------------------- #
class LatencyProbe:
    """DNS kullanmadan ICMP, gerekirse TCP-connect örnekleri toplar.

    ``rounds`` birden büyükse örnekler birden çok turda toplanır; tek bir
    kısa ölçümün rastgele bir hıçkırığa denk gelmesi böylece seçim kararını
    tek başına belirleyemez. ``warmup`` açıkken ilk (ARP/yol açma) turu
    atılır.
    """

    def __init__(self, runner: Runner = run,
                 which_fn: Callable[[str], str | None] = which,
                 samples: int = 5, deadline: int = 5,
                 rounds: int = 1, warmup: bool = False) -> None:
        self.runner = runner
        self.which = which_fn
        self.samples = max(3, int(samples))
        self.deadline = max(2, int(deadline))
        self.rounds = max(1, int(rounds))
        self.warmup = bool(warmup)

    def _ping(self, target: str, interface: str,
              samples: int | None = None) -> tuple[list[float], int]:
        count = self.samples if samples is None else max(1, int(samples))
        cmd = ["ping", "-n", "-c", str(count), "-i", "0.2",
               "-W", "1", "-w", str(self.deadline)]
        if interface:
            cmd.extend(["-I", interface])
        cmd.append(target)
        result = self.runner(cmd, timeout=self.deadline + 2)
        output = str(getattr(result, "stdout", "") or "")
        values = [float(match.group(1)) for match in _PING_TIME_RE.finditer(output)]
        return values, count

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

    def _warm(self, interface: str, gateway: str) -> None:
        """Yol/ARP açılışını ölçüme karıştırma: ilk birkaç paket atılır."""
        for target in ([gateway] if gateway else []) + [
                item for item, _port in _REMOTE_TARGETS[:1]]:
            try:
                self._ping(target, interface, samples=2)
            except Exception as exc:      # ısınma hatası ölçümü engellemez
                log.debug("ısınma turu başarısız: %s", exc)

    def _icmp_round(self, interface: str, gateway: str) -> tuple[
            list[float], int, list[float], list[list[float]], int]:
        gateway_values: list[float] = []
        gateway_sent = 0
        remote_values: list[float] = []
        remote_groups: list[list[float]] = []
        remote_sent = 0
        jobs: list[tuple[str, concurrent.futures.Future]] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            if gateway:
                jobs.append(("gateway", pool.submit(self._ping, gateway, interface)))
            for target, _port in _REMOTE_TARGETS:
                jobs.append(("remote", pool.submit(self._ping, target, interface)))
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
        return (gateway_values, gateway_sent, remote_values, remote_groups,
                remote_sent)

    def _tcp_round(self) -> tuple[list[float], list[list[float]], int]:
        values: list[float] = []
        groups: list[list[float]] = []
        sent = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(self._tcp, target, port, self.samples)
                       for target, port in _REMOTE_TARGETS]
            for future in futures:
                try:
                    batch, batch_sent = future.result()
                except Exception as exc:
                    log.debug("TCP gecikme örneği alınamadı: %s", exc)
                    continue
                values.extend(batch)
                if batch:
                    groups.append(batch)
                sent += batch_sent
        return values, groups, sent

    def measure(self, interface: str, gateway: str) -> LatencyMeasurement:
        ping_available = self.which("ping") is not None
        gateway_values: list[float] = []
        gateway_sent = 0
        remote_values: list[float] = []
        remote_groups: list[list[float]] = []
        remote_sent = 0
        targets = [target for target, _port in _REMOTE_TARGETS]

        if ping_available:
            if self.warmup:
                self._warm(interface, gateway)
            for _round in range(self.rounds):
                (round_gw, round_gw_sent, round_remote, round_groups,
                 round_remote_sent) = self._icmp_round(interface, gateway)
                gateway_values.extend(round_gw)
                gateway_sent += round_gw_sent
                remote_values.extend(round_remote)
                remote_groups.extend(round_groups)
                remote_sent += round_remote_sent

        method = "icmp"
        # Uzak ICMP örneklerinin çoğu kayıpsa endpoint rate-limit'i sonucu
        # yanıltabilir; bu durumda ölçüm türünü tamamen TCP'ye çevir.
        if (not remote_values or
                (remote_sent and len(remote_values) < remote_sent * 0.6)):
            method = "tcp-connect"
            remote_values = []
            remote_groups = []
            remote_sent = 0
            for _round in range(self.rounds):
                batch, groups, sent = self._tcp_round()
                remote_values.extend(batch)
                remote_groups.extend(groups)
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
            rounds=self.rounds,
        )


# --------------------------------------------------------------------------- #
# ağ başına öğrenilen en iyi aday
# --------------------------------------------------------------------------- #
class LatencyProfiles:
    """``NetworkFingerprint.key`` → doğrulanmış en iyi aday belleği."""

    MAX_ENTRIES = 40

    def __init__(self, path: str = LATENCY_PROFILE_FILE) -> None:
        self.path = path
        self.data: dict = {"version": 1, "networks": {}}
        self.load()

    def load(self) -> None:
        try:
            with open(self.path, "r", encoding="utf-8") as handle:
                loaded = json.load(handle)
            if isinstance(loaded, dict) and isinstance(
                    loaded.get("networks"), dict):
                self.data = {"version": 1, "networks": loaded["networks"]}
        except FileNotFoundError:
            pass
        except (OSError, ValueError) as exc:
            log.warning("gecikme profilleri okunamadı: %s", exc)

    def save(self) -> None:
        try:
            directory = os.path.dirname(self.path)
            if directory:
                os.makedirs(directory, mode=0o755, exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as handle:
                json.dump(self.data, handle, ensure_ascii=False)
                handle.write("\n")
            os.replace(tmp, self.path)
        except OSError as exc:
            log.debug("gecikme profilleri yazılamadı: %s", exc)

    def get(self, key: str) -> dict | None:
        if not key:
            return None
        entry = self.data.get("networks", {}).get(key)
        return dict(entry) if isinstance(entry, dict) else None

    def remember(self, key: str, candidate_key: str, label: str,
                 interface: str, gain: dict) -> None:
        if not key or not candidate_key:
            return
        networks = self.data.setdefault("networks", {})
        networks[key] = {
            "candidate": candidate_key,
            "label": label,
            "interface": interface,
            "gain": dict(gain),
            "updated": time.time(),
        }
        if len(networks) > self.MAX_ENTRIES:
            oldest = sorted(networks.items(),
                            key=lambda item: item[1].get("updated", 0))
            for old_key, _value in oldest[:len(networks) - self.MAX_ENTRIES]:
                networks.pop(old_key, None)
        self.save()

    def forget(self, key: str) -> None:
        if self.data.get("networks", {}).pop(key, None) is not None:
            self.save()


# --------------------------------------------------------------------------- #
# düzenleyici
# --------------------------------------------------------------------------- #
class LatencyOptimizer:
    """Taban ölçüm → aday karşılaştırması → en iyi adayın doğrulanması."""

    #: Aday taraması bu süreyi aşarsa kalan adaylar denenmez. Kullanıcı
    #: dakikalarca ölçüm beklemesin.
    BUDGET_SECONDS = 150.0

    def __init__(self, runner: Runner = run,
                 which_fn: Callable[[str], str | None] = which,
                 probe: LatencyProbe | None = None,
                 state_path: str = LATENCY_STATE_FILE,
                 profiles: LatencyProfiles | None = None,
                 profile_path: str = LATENCY_PROFILE_FILE,
                 budget_seconds: float | None = None) -> None:
        self.runner = runner
        self.which = which_fn
        self.probe = probe or LatencyProbe(runner, which_fn, samples=8,
                                           rounds=2, warmup=True)
        self.state_path = state_path
        self.profiles = profiles if profiles is not None else \
            LatencyProfiles(profile_path)
        self.budget_seconds = float(
            self.BUDGET_SECONDS if budget_seconds is None else budget_seconds)
        self.status = LatencyStatus()
        self.snapshot: LatencySnapshot | None = None
        self._lock: asyncio.Lock | None = None
        self._generation = 0
        #: Geri alma sırasında ayarın dışarıdan değiştirildiği görüldüyse
        #: (kullanıcı ya da başka bir program araya girdi) tarama durdurulur:
        #: keşif anındaki taban artık geçerli değildir ve bir sonraki adayı
        #: uygulamak o kişinin ayarını ezerdi.
        self._external_change = ""

    # -- yardımcılar ------------------------------------------------------- #
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

    @staticmethod
    def _rc(result) -> int:
        return int(getattr(result, "returncode", 1) or 0)

    @staticmethod
    def _out(result) -> str:
        return str(getattr(result, "stdout", "") or "")

    async def _measure(self, network: NetworkFingerprint) -> LatencyMeasurement:
        return await self._blocking(
            self.probe.measure, network.interface, network.gateway)

    # ------------------------------------------------------------------ #
    # yaşam döngüsü
    # ------------------------------------------------------------------ #
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
            started = time.monotonic()
            self._external_change = ""
            safe, reason = self._safe_network(network)
            self.status = LatencyStatus(
                enabled=True, interface=network.interface,
                state="measuring" if safe else "unsupported",
                message="Başlangıç gecikmesi ölçülüyor…" if safe else reason,
            )
            if not safe:
                return self.status_dict()

            try:
                return await self._optimize_inner(network, generation, started)
            except LatencyError as exc:
                log.warning("Ping düşürme uygulanamadı: %s", exc)
                return await self._failure(f"Optimizasyon uygulanamadı: {exc}")
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.exception("Ping düşürme akışı hata verdi")
                return await self._failure(f"Optimizasyon uygulanamadı: {exc}")

    def _abort_external(self) -> dict:
        """Ayar dışarıdan değiştiğinde taramayı bitir; kimsenin ayarını ezme."""
        log.warning("Aday taraması durduruldu: %s", self._external_change)
        self.status.state = "external-change"
        self.status.active = False
        self.status.applied = []
        self.status.message = (
            f"{self._external_change}. Ölçüm durduruldu; hiçbir ayar "
            "değiştirilmedi.")
        if self._external_change not in self.status.skipped:
            self.status.skipped.append(self._external_change)
        return self.status_dict()

    async def _failure(self, message: str) -> dict:
        if self.snapshot is not None:
            await self._rollback(f"Optimizasyon hatası; ayarlar geri alındı: "
                                 f"{message}")
        else:
            self.status.state = "failed"
            self.status.message = message
        return self.status_dict()

    async def _optimize_inner(self, network: NetworkFingerprint,
                              generation: int, started: float) -> dict:
        baseline = await self._measure(network)
        self.status.before = baseline
        if self._cancelled(generation):
            return self._cancel_status(network.interface, baseline)
        if not baseline.connected:
            self.status.state = "failed"
            self.status.message = \
                "Bağlantı testi başarısız; hiçbir ayar değiştirilmedi"
            return self.status_dict()

        self.status.state = "applying"
        self.status.message = "Donanıma uygun adaylar hazırlanıyor…"
        environment = await self._discover(network)
        self.status.skipped = list(environment.notes)
        candidates = self._candidates(environment)
        if self._cancelled(generation):
            return self._cancel_status(network.interface, baseline)
        if not candidates:
            already = any("zaten" in note for note in environment.notes)
            self.status.state = "already-optimal" if already else "unsupported"
            self.status.message = (
                "Desteklenen düşük gecikme ayarları zaten etkin"
                if already else
                "Bu ağda desteklenen güvenli optimizasyon bulunamadı")
            return self.status_dict()

        # 1) Bu ağda daha önce doğrulanmış bir aday varsa önce onu sına.
        cached = self.profiles.get(network.key)
        if cached:
            candidate = self._resolve_cached(
                str(cached.get("candidate") or ""), candidates)
            if candidate is None:
                log.info("Kayıtlı aday (%s) bu donanımda geçerli değil; "
                         "yeniden benchmark yapılacak", cached.get("candidate"))
                self.profiles.forget(network.key)
            else:
                result = await self._try_candidate(
                    network, environment, candidate, baseline, generation,
                    keep=True)
                if self._cancelled(generation):
                    await self._rollback("Ağ değişti; eski ayarlar geri alındı")
                    return self.status_dict()
                self.status.candidates = [result]
                if result.verified:
                    return self._activate(candidate, baseline,
                                          result.measurement, cached=True)
                log.info("Kayıtlı aday (%s) artık kazanç sağlamıyor: %s",
                         candidate.key, result.verdict)
                if not await self._restore_current("Kayıtlı aday geri alındı"):
                    return await self._rollback(
                        "Kayıtlı aday geri alınamadı; tarama durduruldu")
                self.status.applied = []
                self.profiles.forget(network.key)
                if self._external_change:
                    return self._abort_external()

        # 2) Tam tarama: her aday ayrı ayrı ölçülür ve hemen geri alınır.
        results: list[CandidateResult] = list(self.status.candidates)
        for candidate in candidates:
            if any(item.key == candidate.key for item in results):
                continue
            if time.monotonic() - started > self.budget_seconds:
                self.status.skipped.append(
                    "Süre bütçesi doldu; kalan adaylar denenmedi")
                break
            result = await self._try_candidate(
                network, environment, candidate, baseline, generation)
            results.append(result)
            self.status.candidates = list(results)
            if self._cancelled(generation):
                await self._rollback("Ağ değişti; eski ayarlar geri alındı")
                return self.status_dict()
            if self._external_change:
                # Keşifteki taban artık geçerli değil: bir sonraki adayı
                # uygulamak, araya giren kişinin ayarını ezerdi.
                return self._abort_external()

        # 3) Kazanç sağlayan birden çok tekil aday varsa birleşimini de dene.
        combined = self._combine(results, candidates)
        if combined is not None and \
                time.monotonic() - started <= self.budget_seconds:
            result = await self._try_candidate(
                network, environment, combined, baseline, generation)
            results.append(result)
            self.status.candidates = list(results)
            candidates = list(candidates) + [combined]
            if self._cancelled(generation):
                await self._rollback("Ağ değişti; eski ayarlar geri alındı")
                return self.status_dict()
            if self._external_change:
                return self._abort_external()

        winner = self._best(results)
        if winner is None:
            self.status.state = "no-gain"
            self.status.message = (
                "Bu ağda doğrulanmış bir gecikme iyileştirmesi bulunamadı; "
                "hiçbir ayar değiştirilmedi")
            self.status.active = False
            self.status.applied = []
            log.info("Ping düşürme: %s", self.status.message)
            return self.status_dict()

        # 4) Kazanan yeniden uygulanır ve bağımsız olarak bir kez daha
        #    doğrulanır. Tek ölçüme güvenilmez.
        candidate = next(item for item in candidates if item.key == winner.key)
        self.status.state = "verifying"
        self.status.message = f"{candidate.label} son kez doğrulanıyor…"
        final = await self._try_candidate(
            network, environment, candidate, baseline, generation, keep=True)
        if self._cancelled(generation):
            await self._rollback("Ağ değişti; eski ayarlar geri alındı")
            return self.status_dict()
        if not final.verified:
            # Tek ölçümlük kazanç yeterli değil. Geri alma başarısız olursa
            # bu, 'kazanç yok' değil bir geri alma hatasıdır; öyle raporlanır.
            self.profiles.forget(network.key)
            if not await self._rollback(
                    "Son doğrulama kazancı tekrarlamadı; ayarlar geri alındı"):
                return self.status_dict()
            self.status.state = "no-gain"
            self.status.applied = []
            self.status.message = (
                "Kazanç son doğrulamada tekrarlanmadı; hiçbir ayar "
                "değiştirilmedi")
            return self.status_dict()

        self.profiles.remember(network.key, candidate.key, candidate.label,
                               network.interface,
                               self._gain(baseline, final.measurement))
        return self._activate(candidate, baseline, final.measurement)

    def _activate(self, candidate: Candidate, baseline: LatencyMeasurement,
                  after: LatencyMeasurement | None, cached: bool = False) -> dict:
        self.status.state = "active"
        self.status.active = True
        self.status.after = after
        self.status.best = candidate.key
        self.status.cached = cached
        self.status.gain = self._gain(baseline, after)
        self.status.message = self._gain_message(baseline, after, cached)
        log.info("Ping düşürme doğrulandı (%s): %s", candidate.key,
                 self.status.message)
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

    # ------------------------------------------------------------------ #
    # ortam keşfi
    # ------------------------------------------------------------------ #
    async def _discover(self, network: NetworkFingerprint) -> Environment:
        env = Environment(interface=network.interface,
                          link_type=network.link_type)
        iface = network.interface

        if network.link_type == "wifi":
            if self.which("iw") is None:
                env.notes.append("iw bulunamadı; Wi-Fi güç tasarrufu atlandı")
            else:
                result = await self._command(
                    ["iw", "dev", iface, "get", "power_save"])
                match = re.search(r"Power save:\s*(on|off)", self._out(result), re.I)
                if self._rc(result) != 0 or match is None:
                    env.notes.append(
                        "Sürücü Wi-Fi güç tasarrufu sorgusunu desteklemiyor")
                else:
                    env.wifi_power_save = match.group(1).lower()
                    if env.wifi_power_save == "off":
                        env.notes.append("Wi-Fi güç tasarrufu zaten kapalı")
        else:
            env.notes.append("Arayüz Wi-Fi değil; güç tasarrufu değişmedi")

        await self._discover_qdisc(env)
        if network.link_type == "ethernet":
            await self._discover_ethtool(env)
        else:
            env.notes.append("Arayüz Ethernet değil; ethtool adayları atlandı")
        return env

    async def _discover_qdisc(self, env: Environment) -> None:
        if self.which("tc") is None:
            env.notes.append("tc bulunamadı; kuyruk disiplini atlandı")
            return
        result = await self._command(["tc", "qdisc", "show", "dev", env.interface])
        if self._rc(result) != 0:
            env.notes.append("Kuyruk disiplini güvenle okunamadı")
            return
        baseline, note = self._qdisc_baseline(self._out(result))
        if baseline is None:
            env.notes.append(note)
            return
        kind, restore_args = baseline
        env.qdisc_kind = kind
        env.qdisc_restore = restore_args
        env.qdisc_replaceable = True
        targets = ["fq_codel", "fq"]
        if await self._cake_available():
            targets.append("cake")
        else:
            env.notes.append("sch_cake çekirdek modülü yok; cake adayı atlandı")
        env.qdisc_targets = tuple(targets)

    async def _cake_available(self) -> bool:
        """``sch_cake`` gerçekten var mı? Denemeden önce sorulur."""
        try:
            if os.path.isdir("/sys/module/sch_cake"):
                return True
            with open("/proc/modules", "r", encoding="ascii",
                      errors="replace") as handle:
                if any(line.startswith("sch_cake ") for line in handle):
                    return True
        except OSError:
            pass
        if self.which("modinfo") is None:
            return False
        result = await self._command(["modinfo", "-F", "filename", "sch_cake"])
        return self._rc(result) == 0 and bool(self._out(result).strip())

    async def _discover_ethtool(self, env: Environment) -> None:
        if self.which("ethtool") is None:
            env.notes.append("ethtool bulunamadı; NIC adayları atlandı")
            return
        # --- Energy Efficient Ethernet -----------------------------------
        result = await self._command(["ethtool", "--show-eee", env.interface])
        if self._rc(result) != 0:
            env.notes.append("Sürücü EEE sorgusunu desteklemiyor")
        else:
            match = re.search(r"EEE status:\s*(\S+)", self._out(result), re.I)
            state = match.group(1).lower() if match else ""
            if state.startswith("enabled"):
                env.eee = "enabled"
            elif state.startswith("disabled"):
                env.eee = "disabled"
                env.notes.append("EEE zaten kapalı")
            else:
                env.notes.append("NIC EEE desteklemiyor; atlandı")

        # --- interrupt coalescing ----------------------------------------
        result = await self._command(["ethtool", "-c", env.interface])
        if self._rc(result) != 0:
            env.notes.append("Sürücü interrupt coalescing sorgusunu desteklemiyor")
            return
        env.coalesce = self._parse_coalesce(self._out(result))
        if not env.coalesce:
            env.notes.append("Coalescing değerleri okunamadı; atlandı")
            return
        # Zaten en düşük gecikmeli değerdeyse dokunmanın anlamı yok.
        adaptive = env.coalesce.get("adaptive-rx", "off")
        try:
            rx_usecs = int(env.coalesce.get("rx-usecs", "0"))
        except ValueError:
            rx_usecs = 0
        env.coalesce_worth_trying = adaptive == "on" or rx_usecs > 0
        if not env.coalesce_worth_trying:
            env.notes.append("RX coalescing zaten en düşük gecikmede")

    @staticmethod
    def _parse_coalesce(output: str) -> dict[str, str]:
        """``ethtool -c`` çıktısından yalnız geri yazılabilir alanları al."""
        values: dict[str, str] = {}
        for line in output.splitlines():
            line = line.strip()
            # TX alanı sürücüye göre "off", "on" ya da "n/a" olabilir; RX
            # değeri ondan bağımsız okunur. (Gerçek çıktı örneği:
            # "Adaptive RX: off  TX: n/a")
            match = re.match(r"^Adaptive RX:\s*(on|off)\b", line, re.I)
            if match:
                values["adaptive-rx"] = match.group(1).lower()
                continue
            match = re.match(r"^(rx-usecs|rx-frames):\s*([0-9]{1,9})\Z", line)
            if match:
                values[match.group(1)] = match.group(2)
        if "adaptive-rx" not in values or "rx-usecs" not in values:
            return {}
        return values

    @staticmethod
    def _qdisc_baseline(output: str) -> tuple[tuple[str, list[str]] | None, str]:
        """Kök qdisc kesin geri yüklenebilir basit bir FIFO mu?

        Değilse dokunulmaz: cake/fq_codel/fq zaten iyi, mq/noqueue yapısal,
        htb gibi custom qdisc'ler ise kullanıcının kasıtlı yapılandırmasıdır.
        """
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        if len(lines) != 1:
            return None, "Custom veya çok katmanlı qdisc korundu"
        match = re.match(
            r"^qdisc\s+(\S+)\s+(\S+)\s+root(?:\s+refcnt\s+\d+)?(?:\s+(.*))?$",
            lines[0])
        if match is None:
            return None, "Qdisc yapısı kesin olarak tanınmadı; korundu"
        kind, handle, options = match.groups()
        if kind in _QDISC_TARGETS:
            return None, f"{kind} zaten etkin; değiştirilmedi"
        if kind in ("mq", "noqueue"):
            return None, f"{kind} qdisc yapısı korundu"
        if kind not in _REPLACEABLE_QDISCS:
            return None, f"Custom qdisc ({kind}) korundu"

        tokens = options.split() if options else []
        restore_options: list[str] = []
        if kind in ("pfifo", "bfifo"):
            # 'limit N' pfifo/bfifo için gerçekten yazılabilir bir seçenektir.
            if len(tokens) != 2 or tokens[0] != "limit" or not re.match(
                    r"^[0-9]+[pb]?\Z", tokens[1]):
                return None, f"Özel {kind} seçenekleri kesin geri alınamıyor; korundu"
            restore_options = list(tokens)
        elif tokens:
            # pfifo_fast'ın bands/priomap değerleri çekirdek sabitidir ve tc
            # bunları KABUL ETMEZ ("qdisc 'pfifo_fast' does not support option
            # parsing"). Görülen değerleri geri yazma tarifine koymak, geri
            # almanın her seferinde başarısız olması demektir; bu yüzden
            # yalnız yapının bozulmamış varsayılan olduğu doğrulanır ve tarife
            # seçenek konmaz.
            if len(tokens) < 3 or tokens[0] != "bands" or "priomap" not in tokens:
                return None, "Özel pfifo_fast yapısı kesin geri alınamıyor; korundu"
            if not all(re.match(r"^[A-Za-z0-9_.:-]+\Z", token) for token in tokens):
                return None, "pfifo_fast seçenekleri güvenli ayrıştırılamadı; korundu"

        restore = []
        if handle != "0:":
            restore.extend(["handle", handle])
        restore.append(kind)
        restore.extend(restore_options)
        return (kind, restore), ""

    # ------------------------------------------------------------------ #
    # aday üretimi
    # ------------------------------------------------------------------ #
    @staticmethod
    def _candidates(env: Environment) -> list[Candidate]:
        """Donanıma göre uyarlanmış aday listesi.

        Wi-Fi ve Ethernet farklı kümeler alır: kablosuzda güç tasarrufu,
        kabloda NIC ayarları. Kuyruk disiplini her ikisinde de yalnızca
        güvenle geri alınabilen bir tabandan başlıyorsa denenir.
        """
        candidates: list[Candidate] = []
        if env.wifi_power_save == "on":
            candidates.append(Candidate(
                key="wifi-power-save", label="Wi-Fi güç tasarrufu kapalı",
                steps=(Step("wifi-power-save", "off",
                            "Wi-Fi güç tasarrufu kapatıldı"),)))
        if env.eee == "enabled":
            candidates.append(Candidate(
                key="eee-off", label="Energy Efficient Ethernet kapalı",
                steps=(Step("eee", "off", "EEE kapatıldı"),)))
        if env.coalesce_worth_trying:
            candidates.append(Candidate(
                key="rx-coalesce", label="Düşük gecikmeli RX coalescing",
                steps=(Step("coalesce", "low",
                            "RX interrupt coalescing düşürüldü"),)))
        if env.qdisc_replaceable:
            for target in env.qdisc_targets:
                candidates.append(Candidate(
                    key=f"qdisc-{target}", label=f"{target} kuyruk disiplini",
                    steps=(Step("qdisc", target, f"{target} uygulandı"),)))
        return candidates

    @staticmethod
    def _resolve_cached(key: str,
                        candidates: Sequence[Candidate]) -> Candidate | None:
        """Kayıtlı aday anahtarını bugünkü donanımın adaylarından yeniden kur.

        Birleşik adaylar ``a+b`` biçiminde saklanır; parçalarının hepsi hâlâ
        geçerliyse aday yeniden üretilir. Bir parça bile geçersizse (örneğin
        qdisc artık değiştirilemez durumda) kayıt geçersiz sayılır ve tam
        benchmark yeniden yapılır.
        """
        if not key:
            return None
        by_key = {item.key: item for item in candidates}
        if key in by_key:
            return by_key[key]
        parts = key.split("+")
        if len(parts) < 2 or not all(part in by_key for part in parts):
            return None
        steps: tuple[Step, ...] = tuple(
            step for part in parts for step in by_key[part].steps)
        return Candidate(key=key,
                         label=" + ".join(by_key[part].label for part in parts),
                         steps=steps)

    @staticmethod
    def _combine(results: Sequence[CandidateResult],
                 candidates: Sequence[Candidate]) -> Candidate | None:
        """Kazanç sağlayan farklı türden adayları tek bir adayda birleştir.

        Aynı türden (örneğin iki qdisc) adaylar birleştirilemez; en iyi puanlı
        olan alınır. En fazla üç adım birleşir.
        """
        by_key = {item.key: item for item in candidates}
        verified = [item for item in results
                    if item.verified and item.score is not None
                    and item.key in by_key]
        if len(verified) < 2:
            return None
        verified.sort(key=lambda item: item.score or 0.0, reverse=True)
        steps: list[Step] = []
        used_kinds: set[str] = set()
        keys: list[str] = []
        for item in verified:
            candidate = by_key[item.key]
            kinds = {step.kind for step in candidate.steps}
            if kinds & used_kinds:
                continue
            if len(steps) + len(candidate.steps) > 3:
                continue
            used_kinds |= kinds
            steps.extend(candidate.steps)
            keys.append(item.key)
        if len(keys) < 2:
            return None
        return Candidate(key="+".join(keys),
                         label=" + ".join(by_key[key].label for key in keys),
                         steps=tuple(steps))

    @staticmethod
    def _best(results: Sequence[CandidateResult]) -> CandidateResult | None:
        winners = [item for item in results
                   if item.verified and item.score is not None]
        if not winners:
            return None
        return max(winners, key=lambda item: item.score or 0.0)

    # ------------------------------------------------------------------ #
    # aday deneme döngüsü
    # ------------------------------------------------------------------ #
    async def _try_candidate(self, network: NetworkFingerprint,
                             env: Environment, candidate: Candidate,
                             baseline: LatencyMeasurement, generation: int,
                             keep: bool = False) -> CandidateResult:
        """Adayı uygula, ölç ve (``keep`` değilse) hemen geri al."""
        result = CandidateResult(key=candidate.key, label=candidate.label)
        self.status.state = "benchmarking" if not keep else "verifying"
        self.status.message = f"{candidate.label} deneniyor…"

        snapshot = LatencySnapshot(interface=env.interface,
                                   link_type=env.link_type,
                                   candidate=candidate.key)
        self.snapshot = snapshot
        try:
            applied = await self._apply(snapshot, candidate, env)
        except LatencyError as exc:
            # Yarım uygulanmış aday: ne kadarı uygulandıysa hepsi geri alınır.
            if not await self._restore_current(
                    f"{candidate.label} uygulanamadı: {exc}"):
                # Geri alınamadıysa sıradaki adaya geçmek sistemi bozuk bir
                # durumda bırakır; akış hata olarak yukarı taşınır.
                raise LatencyError(
                    f"{candidate.label} yarım kaldı ve geri alınamadı: {exc}")
            result.verdict = f"uygulanamadı: {exc}"
            log.info("Aday atlandı (%s): %s", candidate.key, exc)
            return result

        result.applied = applied
        self.status.applied = applied if keep else []
        if self._cancelled(generation):
            result.verdict = "iptal edildi"
            return result

        measurement = await self._measure(network)
        result.measurement = measurement
        verified, verdict = self.evaluate(baseline, measurement)
        result.verified = verified
        result.verdict = verdict
        result.score = self.score(baseline, measurement)
        log.info("Aday %s: %s (puan %s)", candidate.key, verdict,
                 "-" if result.score is None else f"{result.score:.2f}")

        if not keep:
            if not await self._restore_current(""):
                # Geri alınamayan aday: durumu bozuk bırakmamak için akış
                # yukarıda hata olarak ele alınır.
                raise LatencyError(
                    f"{candidate.label} sonrası eski ayarlar geri alınamadı")
        return result

    async def _apply(self, snapshot: LatencySnapshot, candidate: Candidate,
                     env: Environment) -> list[str]:
        """Adımları sırayla uygula; her adımın tarifi **uygulamadan önce** yazılır.

        Sıra kasıtlı: komut yarıda kalsa ya da servis tam o anda çökse bile
        geri alma tarifi diskte hazırdır. Hiç değişmemiş bir ayarı geri almak
        zararsız bir no-op'tur; değişmiş ama tarifi kaydedilmemiş bir ayar ise
        kalıcı bozukluk demektir.
        """
        applied: list[str] = []
        for step in candidate.steps:
            action = self._prepare_action(step, env)
            snapshot.actions.append(action)
            self._save_snapshot(snapshot)
            await self._run_step(step, env)
            action.signature = await self._read_signature(step, env)
            self._save_snapshot(snapshot)
            applied.append(action.label)
        return applied

    @staticmethod
    def _prepare_action(step: Step, env: Environment) -> ActionSnapshot:
        """Adımın geri alma tarifini üretir; hiçbir şeyi değiştirmez."""
        iface = env.interface
        if step.kind == "wifi-power-save":
            return ActionSnapshot(
                kind="wifi-power-save", interface=iface,
                restore={"value": env.wifi_power_save or "on"},
                label="Wi-Fi güç tasarrufu kapatıldı")
        if step.kind == "qdisc":
            if not env.qdisc_replaceable:
                raise LatencyError("qdisc tabanı kayboldu")
            return ActionSnapshot(
                kind="qdisc", interface=iface,
                restore={"kind": env.qdisc_kind, "args": list(env.qdisc_restore)},
                label=f"{step.target} uygulandı")
        if step.kind == "eee":
            return ActionSnapshot(
                kind="eee", interface=iface,
                restore={"value": "on" if env.eee == "enabled" else "off"},
                label="EEE kapatıldı")
        if step.kind == "coalesce":
            params = {key: value for key, value in env.coalesce.items()
                      if key in _COALESCE_KEYS}
            if not params:
                raise LatencyError("coalescing tabanı okunamadı")
            return ActionSnapshot(
                kind="coalesce", interface=iface, restore={"params": params},
                label="RX interrupt coalescing düşürüldü")
        raise LatencyError(f"bilinmeyen aday adımı: {step.kind}")

    async def _run_step(self, step: Step, env: Environment) -> None:
        """Adımı gerçekten uygula ve sonucu doğrula."""
        iface = env.interface
        if step.kind == "wifi-power-save":
            result = await self._command(
                ["iw", "dev", iface, "set", "power_save", step.target])
            if self._rc(result) != 0:
                raise LatencyError("Wi-Fi güç tasarrufu kapatılamadı")
            return

        if step.kind == "qdisc":
            result = await self._command(
                ["tc", "qdisc", "replace", "dev", iface, "root", step.target])
            if self._rc(result) != 0:
                raise LatencyError(f"{step.target} uygulanamadı")
            current = await self._command(["tc", "qdisc", "show", "dev", iface])
            output = self._normalize(self._out(current))
            if (self._rc(current) != 0 or
                    not output.startswith(f"qdisc {step.target} ") or
                    "\n" in output):
                raise LatencyError(f"uygulanan {step.target} doğrulanamadı")
            return

        if step.kind == "eee":
            result = await self._command(
                ["ethtool", "--set-eee", iface, "eee", step.target])
            if self._rc(result) != 0:
                # Sürücü yazmayı desteklemiyor: hata değil, atlanacak aday.
                raise LatencyError("Sürücü EEE ayarını değiştirmeyi desteklemiyor")
            return

        if step.kind == "coalesce":
            result = await self._command(
                ["ethtool", "-C", iface, "adaptive-rx", "off", "rx-usecs", "0"])
            if self._rc(result) != 0:
                raise LatencyError(
                    "Sürücü interrupt coalescing ayarını desteklemiyor")
            return

        raise LatencyError(f"bilinmeyen aday adımı: {step.kind}")

    async def _read_signature(self, step: Step, env: Environment) -> str:
        """Uygulama sonrası durumu oku; dışarıdan değişiklik böyle saptanır."""
        iface = env.interface
        if step.kind == "qdisc":
            current = await self._command(["tc", "qdisc", "show", "dev", iface])
            return self._normalize(self._out(current)) if self._rc(current) == 0 else ""
        if step.kind == "coalesce":
            current = await self._command(["ethtool", "-c", iface])
            if self._rc(current) != 0:
                return ""
            values = self._parse_coalesce(self._out(current))
            return json.dumps(values, sort_keys=True)
        return ""

    # ------------------------------------------------------------------ #
    # geri alma
    # ------------------------------------------------------------------ #
    async def _restore_current(self, message: str) -> bool:
        """Bellekteki/dosyadaki snapshot'ı geri al ve temizle."""
        snapshot = self.snapshot or self._load_snapshot()
        ok = True if snapshot is None else await self._restore(snapshot)
        if ok:
            self._drop_snapshot()
            self.snapshot = None
        elif message:
            log.error("%s — geri alma başarısız", message)
        return ok

    async def _rollback(self, message: str) -> bool:
        ok = await self._restore_current(message)
        self.status.active = not ok
        self.status.applied = [] if ok else self.status.applied
        self.status.state = "rolled-back" if ok else "rollback-failed"
        self.status.message = message if ok else (
            "Ayarların tamamı geri alınamadı; servis günlüğünü kontrol edin")
        log.info("Ping düşürme sonucu: %s", self.status.message)
        return ok

    async def _restore(self, snapshot: LatencySnapshot) -> bool:
        ok = True
        # Uygulama sırasının tersi.
        for action in reversed(snapshot.actions):
            if not await self._restore_action(action):
                ok = False
        return ok

    async def _restore_action(self, action: ActionSnapshot) -> bool:
        iface = action.interface
        if action.kind == "qdisc":
            if self.which("tc") is None:
                log.error("qdisc geri alınamadı: tc bulunamadı")
                return False
            if action.signature:
                current = await self._command(["tc", "qdisc", "show", "dev", iface])
                if self._rc(current) != 0:
                    log.error("%s güncel qdisc okunamadı", iface)
                    return False
                if self._normalize(self._out(current)) != action.signature:
                    log.warning("%s qdisc dışarıdan değiştirildi; custom yapı "
                                "korunuyor", iface)
                    self._external_change = (
                        f"{iface} kuyruk disiplini dışarıdan değiştirildi; "
                        "kullanıcı ayarı korundu")
                    return True
            cmd = (["tc", "qdisc", "replace", "dev", iface, "root"]
                   + list(action.restore.get("args", [])))
            result = await self._command(cmd)
            if self._rc(result) != 0:
                log.error("%s qdisc geri alınamadı", iface)
                return False
            return True

        if action.kind == "wifi-power-save":
            if self.which("iw") is None:
                log.error("Wi-Fi güç tasarrufu geri alınamadı: iw bulunamadı")
                return False
            result = await self._command(
                ["iw", "dev", iface, "set", "power_save",
                 action.restore.get("value", "on")])
            if self._rc(result) != 0:
                log.error("%s Wi-Fi güç tasarrufu geri alınamadı", iface)
                return False
            return True

        if action.kind == "eee":
            if self.which("ethtool") is None:
                log.error("EEE geri alınamadı: ethtool bulunamadı")
                return False
            result = await self._command(
                ["ethtool", "--set-eee", iface, "eee",
                 action.restore.get("value", "on")])
            if self._rc(result) != 0:
                log.error("%s EEE ayarı geri alınamadı", iface)
                return False
            return True

        if action.kind == "coalesce":
            if self.which("ethtool") is None:
                log.error("coalescing geri alınamadı: ethtool bulunamadı")
                return False
            if action.signature:
                current = await self._command(["ethtool", "-c", iface])
                if self._rc(current) != 0:
                    log.error("%s coalescing durumu okunamadı", iface)
                    return False
                live = json.dumps(self._parse_coalesce(self._out(current)),
                                  sort_keys=True)
                if live != action.signature:
                    log.warning("%s coalescing dışarıdan değiştirildi; kullanıcı "
                                "ayarı korunuyor", iface)
                    self._external_change = (
                        f"{iface} coalescing ayarı dışarıdan değiştirildi; "
                        "kullanıcı ayarı korundu")
                    return True
            params = action.restore.get("params", {})
            cmd = ["ethtool", "-C", iface]
            for key in _COALESCE_KEYS:
                if key in params:
                    cmd.extend([key, str(params[key])])
            result = await self._command(cmd)
            if self._rc(result) != 0:
                log.error("%s coalescing geri alınamadı", iface)
                return False
            return True

        log.error("bilinmeyen eylem geri alınamadı: %s", action.kind)
        return False

    def restore_persisted_sync(self) -> bool:
        """``dpi-bypassd --cleanup`` için olay döngüsüz geri alma yolu."""
        snapshot = self._load_snapshot()
        if snapshot is None:
            return True
        ok = True
        for action in reversed(snapshot.actions):
            iface = action.interface
            if action.kind == "qdisc":
                if action.signature:
                    current = self.runner(
                        ["tc", "qdisc", "show", "dev", iface], timeout=8)
                    if self._rc(current) != 0:
                        ok = False
                        continue
                    if self._normalize(self._out(current)) != action.signature:
                        log.warning("%s qdisc dışarıdan değiştirildi; custom "
                                    "yapı korunuyor", iface)
                        continue
                result = self.runner(
                    ["tc", "qdisc", "replace", "dev", iface, "root"]
                    + list(action.restore.get("args", [])), timeout=8)
                ok = self._rc(result) == 0 and ok
            elif action.kind == "wifi-power-save":
                result = self.runner(
                    ["iw", "dev", iface, "set", "power_save",
                     action.restore.get("value", "on")], timeout=8)
                ok = self._rc(result) == 0 and ok
            elif action.kind == "eee":
                result = self.runner(
                    ["ethtool", "--set-eee", iface, "eee",
                     action.restore.get("value", "on")], timeout=8)
                ok = self._rc(result) == 0 and ok
            elif action.kind == "coalesce":
                if action.signature:
                    current = self.runner(["ethtool", "-c", iface], timeout=8)
                    if self._rc(current) != 0:
                        ok = False
                        continue
                    live = json.dumps(self._parse_coalesce(self._out(current)),
                                      sort_keys=True)
                    if live != action.signature:
                        log.warning("%s coalescing dışarıdan değiştirildi; "
                                    "kullanıcı ayarı korunuyor", iface)
                        continue
                params = action.restore.get("params", {})
                cmd = ["ethtool", "-C", iface]
                for key in _COALESCE_KEYS:
                    if key in params:
                        cmd.extend([key, str(params[key])])
                result = self.runner(cmd, timeout=8)
                ok = self._rc(result) == 0 and ok
            else:
                ok = False
        if ok:
            self._drop_snapshot()
        return ok

    # ------------------------------------------------------------------ #
    # snapshot dosyası
    # ------------------------------------------------------------------ #
    @staticmethod
    def _normalize(output: str) -> str:
        return "\n".join(line.strip() for line in output.splitlines()
                         if line.strip())

    def _save_snapshot(self, snapshot: LatencySnapshot) -> None:
        directory = os.path.dirname(self.state_path)
        if directory:
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

    # ------------------------------------------------------------------ #
    # değerlendirme
    # ------------------------------------------------------------------ #
    @staticmethod
    def evaluate(before: LatencyMeasurement,
                 after: LatencyMeasurement) -> tuple[bool, str]:
        """Ölçülen fark gürültü mü, gerçek kazanç mı?

        Kötüleşme eşikleri kazanç eşiklerinden geniştir: şüphede kalırsak
        değişiklik geri alınır. Oyun/gerçek zamanlı trafik için p95 ve jitter
        en az median kadar önemlidir, bu yüzden üçü de ayrı ayrı bakılır.
        """
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
    def score(before: LatencyMeasurement,
              after: LatencyMeasurement | None) -> float | None:
        """Adayları sıralamak için tek sayı.

        Ağırlıklar oyun trafiğine göre: p95 ve jitter, median kadar (hatta
        birlikte daha fazla) önemlidir. Paket kaybı ağır cezalandırılır.
        """
        if after is None or not after.connected:
            return None
        old, new = before.remote, after.remote
        if old.median_ms is None or new.median_ms is None:
            return None
        total = 0.4 * (old.median_ms - new.median_ms)
        if old.p95_ms is not None and new.p95_ms is not None:
            total += 0.4 * (old.p95_ms - new.p95_ms)
        if old.jitter_ms is not None and new.jitter_ms is not None:
            total += 0.2 * (old.jitter_ms - new.jitter_ms)
        total -= 5.0 * max(0.0, new.packet_loss - old.packet_loss)
        return round(total, 3)

    @staticmethod
    def _gain(before: LatencyMeasurement,
              after: LatencyMeasurement | None) -> dict:
        if after is None:
            return {}
        old, new = before.remote, after.remote

        def delta(first: float | None, second: float | None) -> float | None:
            if first is None or second is None:
                return None
            return round(second - first, 2)

        return {
            "median_ms": delta(old.median_ms, new.median_ms),
            "p95_ms": delta(old.p95_ms, new.p95_ms),
            "jitter_ms": delta(old.jitter_ms, new.jitter_ms),
            "packet_loss": delta(old.packet_loss, new.packet_loss),
        }

    @classmethod
    def _gain_message(cls, before: LatencyMeasurement,
                      after: LatencyMeasurement | None,
                      cached: bool = False) -> str:
        if after is None:
            return "Doğrulandı"
        old, new = before.remote, after.remote
        parts = [f"median {old.median_ms:g} → {new.median_ms:g} ms"]
        if old.p95_ms is not None and new.p95_ms is not None:
            parts.append(f"p95 {old.p95_ms:g} → {new.p95_ms:g} ms")
        if old.jitter_ms is not None and new.jitter_ms is not None:
            parts.append(f"jitter {old.jitter_ms:g} → {new.jitter_ms:g} ms")
        prefix = "Doğrulandı (bu ağda kayıtlı ayar)" if cached else "Doğrulandı"
        return f"{prefix}: " + " · ".join(parts)

    @staticmethod
    def _measurement_message(measurement: LatencyMeasurement) -> str:
        remote = measurement.remote
        return (f"{remote.median_ms:g} ms median · {remote.p95_ms:g} ms p95 · "
                f"{remote.jitter_ms:g} ms jitter · %{remote.packet_loss:g} kayıp")
