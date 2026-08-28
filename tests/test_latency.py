"""Ping düşürme kipinin ağdan ve root yetkisinden bağımsız testleri.

Aday motoru gerçek komut çalıştırmaz: ``FakeRunner`` sistemin durumunu
(``iw``/``tc``/``ethtool``) taklit eder, ``StateProbe`` ise ölçümü o duruma
göre üretir. Böylece "aday A daha iyi", "aday B daha da iyi", "hiçbiri iyi
değil" gibi senaryolar deterministik olarak sınanabilir.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "src"))

from dpibypass.config import Config, DEFAULTS  # noqa: E402
from dpibypass.latency import (LatencyMeasurement, LatencyOptimizer,  # noqa: E402
                               LatencyProbe, LatencyProfiles, LatencySnapshot,
                               LatencyStats)
from dpibypass.netmon import NetworkFingerprint  # noqa: E402


def network(interface: str = "wlan0", link_type: str = "wifi",
            gateway: str = "192.0.2.1", ssid: str = "Test") -> NetworkFingerprint:
    return NetworkFingerprint(interface=interface, gateway=gateway,
                              link_type=link_type, ssid=ssid)


def measurement(median: float = 24.0, jitter: float = 4.0,
                p95: float | None = None, loss: float = 0.0,
                connected: bool = True) -> LatencyMeasurement:
    received = 5 if connected else 0
    remote = LatencyStats(
        sent=5, received=received,
        median_ms=median if connected else None,
        minimum_ms=max(0.1, median - 3) if connected else None,
        p95_ms=(p95 if p95 is not None else median + 4) if connected else None,
        jitter_ms=jitter if connected else None,
        spread_ms=7.0 if connected else None,
        packet_loss=loss if connected else 100.0,
    )
    gateway = LatencyStats(
        sent=5, received=5, median_ms=2.0, minimum_ms=1.0,
        p95_ms=3.0, jitter_ms=0.5, spread_ms=2.0, packet_loss=0.0)
    return LatencyMeasurement("icmp", gateway, remote,
                              ["192.0.2.1", "1.1.1.1"])


class FakeProbe:
    """Sırayla önceden verilmiş ölçümleri döndürür."""

    def __init__(self, *results: LatencyMeasurement) -> None:
        self.results = list(results)
        self.calls: list[tuple[str, str]] = []

    def measure(self, interface: str, gateway: str) -> LatencyMeasurement:
        self.calls.append((interface, gateway))
        if not self.results:
            raise AssertionError("Beklenmeyen ek ölçüm")
        return self.results.pop(0)


class StateProbe:
    """Ölçümü, FakeRunner üzerindeki gerçek sistem durumundan üretir.

    Aday motoru her adayı uygulayıp geri aldığı için ölçüm sırası önceden
    bilinemez; sonucu duruma bağlamak testleri sıralamadan bağımsız kılar.
    """

    def __init__(self, runner: "FakeRunner", table: dict,
                 default: LatencyMeasurement) -> None:
        self.runner = runner
        self.table = table
        self.default = default
        self.calls: list[tuple[str, str]] = []

    def state_key(self, interface: str) -> tuple:
        qdisc = self.runner.qdisc.get(interface, "")
        kind = qdisc.split()[1] if qdisc.startswith("qdisc ") else ""
        return (self.runner.power.get(interface, "off"), kind,
                self.runner.eee.get(interface, "disabled"),
                self.runner.coalesce.get(interface, {}).get("adaptive-rx", "off"))

    def measure(self, interface: str, gateway: str) -> LatencyMeasurement:
        self.calls.append((interface, gateway))
        key = self.state_key(interface)
        for candidate_key, value in self.table.items():
            if all(part is None or part == key[index]
                   for index, part in enumerate(candidate_key)):
                return value
        return self.default


class FakeRunner:
    """iw / tc / ethtool davranışının test kopyası."""

    def __init__(self, tools=("iw", "tc")) -> None:
        self.tools = set(tools)
        self.calls: list[list[str]] = []
        self.power: dict[str, str] = {"wlan0": "on", "wlan1": "on"}
        self.qdisc: dict[str, str] = {
            "wlan0": "qdisc fq_codel 0: root refcnt 2 limit 10240p",
            "wlan1": "qdisc fq_codel 0: root refcnt 2 limit 10240p",
            "eth0": "qdisc fq_codel 0: root refcnt 2 limit 10240p",
            "eth1": "qdisc fq_codel 0: root refcnt 2 limit 10240p",
        }
        self.eee: dict[str, str] = {}
        self.eee_supported = True
        self.coalesce: dict[str, dict[str, str]] = {}
        self.coalesce_supported = True
        self.fail_fq_codel_once = False
        self.fail_qdisc_kinds: set[str] = set()

    def which(self, name: str) -> str | None:
        return f"/usr/sbin/{name}" if name in self.tools else None

    # -- yardımcılar -------------------------------------------------------
    def set_ethernet(self, iface: str = "eth0", eee: str = "enabled",
                     adaptive_rx: str = "on", rx_usecs: str = "50") -> None:
        self.tools.add("ethtool")
        self.eee[iface] = eee
        self.coalesce[iface] = {"adaptive-rx": adaptive_rx,
                                "rx-usecs": rx_usecs, "rx-frames": "0"}

    def replaced(self, iface: str = "") -> list[list[str]]:
        return [call for call in self.calls
                if call[:3] == ["tc", "qdisc", "replace"]
                and (not iface or call[4] == iface)]

    # -- komutlar ----------------------------------------------------------
    def __call__(self, cmd, **_kwargs):
        cmd = list(cmd)
        self.calls.append(cmd)
        if cmd[:2] == ["iw", "dev"] and cmd[3:] == ["get", "power_save"]:
            state = self.power.get(cmd[2], "off")
            return subprocess.CompletedProcess(cmd, 0, f"Power save: {state}\n", "")
        if cmd and cmd[0] == "iw" and cmd[3:5] == ["set", "power_save"]:
            self.power[cmd[2]] = cmd[5]
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if cmd[:3] == ["tc", "qdisc", "show"]:
            iface = cmd[-1]
            return subprocess.CompletedProcess(
                cmd, 0, self.qdisc.get(iface, "qdisc noqueue 0: root\n") + "\n", "")
        if cmd[:3] == ["tc", "qdisc", "replace"]:
            iface = cmd[4]
            args = cmd[6:]
            if args == ["fq_codel"] and self.fail_fq_codel_once:
                self.fail_fq_codel_once = False
                return subprocess.CompletedProcess(cmd, 2, "", "uygulanamadı")
            if args and args[0] in self.fail_qdisc_kinds:
                return subprocess.CompletedProcess(cmd, 2, "", "desteklenmiyor")
            kind_index = 1 if args[:1] == ["handle"] else 0
            if kind_index:
                kind_index = 2
            kind = args[kind_index]
            options = " ".join(args[kind_index + 1:])
            self.qdisc[iface] = (f"qdisc {kind} 0: root refcnt 2 "
                                 f"{options}").strip()
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if cmd[:2] == ["ethtool", "--show-eee"]:
            if not self.eee_supported:
                return subprocess.CompletedProcess(
                    cmd, 75, "", "netlink error: Operation not supported")
            state = self.eee.get(cmd[2], "unsupported")
            body = "enabled - active" if state == "enabled" else state
            return subprocess.CompletedProcess(
                cmd, 0, f"EEE settings for {cmd[2]}:\n\tEEE status: {body}\n", "")
        if cmd[:2] == ["ethtool", "--set-eee"]:
            if not self.eee_supported:
                return subprocess.CompletedProcess(cmd, 75, "", "not supported")
            self.eee[cmd[2]] = "enabled" if cmd[4] == "on" else "disabled"
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if cmd[:2] == ["ethtool", "-c"]:
            if not self.coalesce_supported or cmd[2] not in self.coalesce:
                return subprocess.CompletedProcess(cmd, 75, "", "not supported")
            values = self.coalesce[cmd[2]]
            text = (f"Coalesce parameters for {cmd[2]}:\n"
                    f"Adaptive RX: {values['adaptive-rx']}  TX: off\n"
                    f"rx-usecs: {values['rx-usecs']}\n"
                    f"rx-frames: {values['rx-frames']}\n")
            return subprocess.CompletedProcess(cmd, 0, text, "")
        if cmd[:2] == ["ethtool", "-C"]:
            if not self.coalesce_supported or cmd[2] not in self.coalesce:
                return subprocess.CompletedProcess(cmd, 75, "", "not supported")
            pairs = cmd[3:]
            for index in range(0, len(pairs) - 1, 2):
                self.coalesce[cmd[2]][pairs[index]] = pairs[index + 1]
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if cmd[:1] == ["modinfo"]:
            return subprocess.CompletedProcess(cmd, 1, "", "not found")
        return subprocess.CompletedProcess(cmd, 0, "", "")


class OptimizerCase(unittest.IsolatedAsyncioTestCase):
    def temp_dir(self) -> str:
        directory = tempfile.TemporaryDirectory(prefix="dpibypass-latency-")
        self.addCleanup(directory.cleanup)
        return directory.name

    def make_optimizer(self, runner: FakeRunner, probe,
                       directory: str | None = None) -> LatencyOptimizer:
        directory = directory or self.temp_dir()
        return LatencyOptimizer(
            runner=runner, which_fn=runner.which, probe=probe,
            state_path=os.path.join(directory, "latency.json"),
            profile_path=os.path.join(directory, "profiles.json"))


class TestLatencyConfig(unittest.TestCase):
    def test_default_is_disabled(self):
        self.assertIs(DEFAULTS["latency_mode"], False)
        config = Config(path="/definitely/missing/dpi-bypass-config.json")
        self.assertIs(config["latency_mode"], False)

    def test_old_config_loads_without_migration(self):
        with tempfile.TemporaryDirectory(prefix="dpibypass-config-") as directory:
            path = os.path.join(directory, "config.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump({"enabled": False, "mode": "all"}, handle)
            config = Config(path=path)
        self.assertFalse(config["enabled"])
        self.assertEqual(config["mode"], "all")
        self.assertFalse(config["latency_mode"])


class TestLatencyMetrics(unittest.TestCase):
    def test_median_p95_jitter_and_loss(self):
        stats = LatencyStats.from_samples([10, 12, 11, 30], sent=5)
        self.assertEqual(stats.minimum_ms, 10)
        self.assertEqual(stats.median_ms, 11.5)
        self.assertEqual(stats.p95_ms, 30)
        self.assertAlmostEqual(stats.jitter_ms, 7.33, places=2)
        self.assertEqual(stats.spread_ms, 20)
        self.assertEqual(stats.packet_loss, 20)

    def test_one_ms_noise_is_not_a_verified_gain(self):
        ok, message = LatencyOptimizer.evaluate(
            measurement(median=20, jitter=4),
            measurement(median=19, jitter=3.8))
        self.assertFalse(ok)
        self.assertIn("doğrulanmış", message)

    def test_clear_improvement_is_accepted(self):
        ok, message = LatencyOptimizer.evaluate(
            measurement(median=25, jitter=8, p95=55),
            measurement(median=20, jitter=3, p95=31))
        self.assertTrue(ok)
        self.assertEqual(message, "doğrulandı")

    def test_icmp_collects_gateway_and_remote_samples(self):
        def runner(cmd, **_kwargs):
            target = cmd[-1]
            base = {"192.0.2.1": 1, "1.1.1.1": 20, "8.8.8.8": 100}[target]
            output = "\n".join(
                f"64 bytes from {target}: time={base + index}.0 ms"
                for index in range(5))
            return subprocess.CompletedProcess(cmd, 0, output, "")

        probe = LatencyProbe(runner=runner, which_fn=lambda _name: "/bin/ping")
        result = probe.measure("eth0", "192.0.2.1")
        self.assertEqual(result.method, "icmp")
        self.assertEqual(result.gateway.median_ms, 3)
        self.assertEqual(result.remote.median_ms, 62)
        self.assertEqual(result.remote.jitter_ms, 1)
        self.assertEqual(result.remote.packet_loss, 0)

    def test_multiple_rounds_aggregate_samples(self):
        """Tek tur yerine birden çok tur: gürültü tek ölçümde kalmasın."""
        def runner(cmd, **_kwargs):
            target = cmd[-1]
            output = "\n".join(
                f"64 bytes from {target}: time=20.0 ms" for _index in range(5))
            return subprocess.CompletedProcess(cmd, 0, output, "")

        probe = LatencyProbe(runner=runner, which_fn=lambda _name: "/bin/ping",
                             rounds=3)
        result = probe.measure("eth0", "192.0.2.1")
        self.assertEqual(result.rounds, 3)
        self.assertEqual(result.remote.sent, 30)      # 2 hedef × 5 × 3 tur
        self.assertEqual(result.remote.received, 30)
        self.assertEqual(result.gateway.sent, 15)

    def test_warmup_samples_are_not_counted(self):
        seen: list[list[str]] = []

        def runner(cmd, **_kwargs):
            seen.append(list(cmd))
            return subprocess.CompletedProcess(
                cmd, 0, "time=20.0 ms\n" * int(cmd[cmd.index("-c") + 1]), "")

        probe = LatencyProbe(runner=runner, which_fn=lambda _name: "/bin/ping",
                             samples=5, warmup=True)
        result = probe.measure("eth0", "192.0.2.1")
        self.assertTrue(any(call[call.index("-c") + 1] == "2" for call in seen),
                        "ısınma turu çalışmadı")
        self.assertEqual(result.remote.sent, 10)      # ısınma sayılmaz

    def test_tcp_fallback_does_not_require_dns(self):
        probe = LatencyProbe(
            runner=lambda *_args, **_kwargs: self.fail("ping çalışmamalı"),
            which_fn=lambda _name: None)
        with mock.patch.object(
                LatencyProbe, "_tcp",
                return_value=([18.0, 20.0, 19.0, 21.0, 22.0], 5)):
            result = probe.measure("eth0", "192.0.2.1")
        self.assertEqual(result.method, "tcp-connect")
        self.assertEqual(result.remote.received, 10)
        self.assertEqual(result.remote.median_ms, 20)
        self.assertEqual(result.gateway.received, 0)

    def test_partial_icmp_samples_are_discarded_before_tcp_fallback(self):
        def runner(cmd, **_kwargs):
            target = cmd[-1]
            count = 5 if target == "192.0.2.1" else 1
            output = "\n".join(
                f"64 bytes from {target}: time=20.0 ms"
                for _index in range(count))
            return subprocess.CompletedProcess(cmd, 0, output, "")

        probe = LatencyProbe(runner=runner, which_fn=lambda _name: "/bin/ping")
        with mock.patch.object(
                LatencyProbe, "_tcp",
                return_value=([18.0, 20.0, 19.0, 21.0, 22.0], 5)):
            result = probe.measure("eth0", "192.0.2.1")
        self.assertEqual(result.method, "tcp-connect")
        self.assertEqual(result.remote.received, 10)
        self.assertEqual(result.remote.packet_loss, 0)

    def test_different_measurement_methods_are_not_compared(self):
        before = measurement(25, 4)
        after = measurement(20, 2)
        after.method = "tcp-connect"
        ok, message = LatencyOptimizer.evaluate(before, after)
        self.assertFalse(ok)
        self.assertIn("Ölçüm yöntemi değişti", message)

    def test_score_weights_p95_and_jitter(self):
        base = measurement(30, 8, p95=60)
        better_p95 = measurement(30, 8, p95=40)
        better_median = measurement(25, 8, p95=60)
        self.assertGreater(LatencyOptimizer.score(base, better_p95),
                           LatencyOptimizer.score(base, better_median))

    def test_coalesce_parsing_handles_real_driver_output(self):
        """Gerçek 'ethtool -c' çıktısı: TX alanı 'n/a', değerler sekmeli."""
        text = (
            "Coalesce parameters for eth0:\n"
            "Adaptive RX: off  TX: n/a\n"
            "stats-block-usecs:\tn/a\n"
            "sample-interval:\tn/a\n"
            "\n"
            "rx-usecs:\t0\n"
            "rx-frames:\t0\n"
            "tx-usecs:\tn/a\n")
        values = LatencyOptimizer._parse_coalesce(text)
        self.assertEqual(values["adaptive-rx"], "off")
        self.assertEqual(values["rx-usecs"], "0")
        self.assertEqual(values["rx-frames"], "0")

    def test_coalesce_parsing_rejects_unreadable_output(self):
        for text in ("", "netlink error: Operation not supported\n",
                     "Coalesce parameters for eth0:\nrx-usecs:\tn/a\n"):
            with self.subTest(text=text):
                self.assertEqual(LatencyOptimizer._parse_coalesce(text), {})

    def test_score_penalises_packet_loss(self):
        base = measurement(30, 6, loss=0)
        lossy = measurement(20, 2, loss=5)
        self.assertLess(LatencyOptimizer.score(base, lossy), 0)


class TestStatusRendering(unittest.TestCase):
    """CLI özet satırı: geri alma hatası 'doğrulandı' diye gösterilmemeli."""

    def line(self, **latency) -> str:
        from dpibypass.cli import _latency_line
        return _latency_line(latency)

    def test_rollback_failure_is_not_reported_as_verified(self):
        text = self.line(enabled=True, active=True, state="rollback-failed",
                         message="Ayarların tamamı geri alınamadı")
        self.assertIn("geri alınamadı", text)
        self.assertNotIn("doğrulandı", text)

    def test_verified_state_is_reported_as_verified(self):
        text = self.line(enabled=True, active=True, state="active",
                         message="median 30 → 21 ms")
        self.assertIn("doğrulandı", text)

    def test_no_gain_is_explicit(self):
        text = self.line(enabled=True, active=False, state="no-gain",
                         message="Bu ağda doğrulanmış bir iyileştirme yok")
        self.assertIn("kazanç yok", text)

    def test_disabled_and_rolled_back_read_as_off(self):
        for state in ("disabled", "rolled-back"):
            with self.subTest(state=state):
                self.assertIn("kapalı", self.line(
                    enabled=False, active=False, state=state, message="Kapalı"))


class TestLatencyPlanning(OptimizerCase):
    async def test_non_wifi_never_touches_power_save(self):
        runner = FakeRunner()
        optimizer = self.make_optimizer(runner, FakeProbe(measurement()))
        await optimizer.optimize(network("eth0", "ethernet"))
        self.assertFalse(any(call[0] == "iw" for call in runner.calls))

    async def test_missing_iw_is_a_graceful_skip(self):
        runner = FakeRunner(tools=("tc",))
        optimizer = self.make_optimizer(runner, FakeProbe(measurement()))
        status = await optimizer.optimize(network())
        self.assertIn("iw bulunamadı", " ".join(status["skipped"]))
        self.assertEqual(status["state"], "already-optimal")

    async def test_missing_tc_is_a_graceful_skip(self):
        runner = FakeRunner(tools=("iw",))
        runner.power["wlan0"] = "off"
        optimizer = self.make_optimizer(runner, FakeProbe(measurement()))
        status = await optimizer.optimize(network())
        self.assertIn("tc bulunamadı", " ".join(status["skipped"]))
        self.assertFalse(any(call[:1] == ["tc"] for call in runner.calls))

    async def test_missing_ethtool_is_a_graceful_skip(self):
        runner = FakeRunner(tools=("tc",))
        optimizer = self.make_optimizer(runner, FakeProbe(measurement()))
        status = await optimizer.optimize(network("eth0", "ethernet"))
        self.assertIn("ethtool bulunamadı", " ".join(status["skipped"]))
        self.assertFalse(any(call[:1] == ["ethtool"] for call in runner.calls))

    async def test_unsupported_ethtool_driver_is_not_an_error(self):
        runner = FakeRunner(tools=("tc", "ethtool"))
        runner.eee_supported = False
        runner.coalesce_supported = False
        optimizer = self.make_optimizer(runner, FakeProbe(measurement()))
        status = await optimizer.optimize(network("eth0", "ethernet"))
        self.assertNotEqual(status["state"], "failed")
        skipped = " ".join(status["skipped"])
        self.assertIn("EEE", skipped)
        self.assertIn("coalescing", skipped)

    async def test_existing_safe_qdiscs_are_preserved(self):
        cases = {
            "cake": "qdisc cake 8001: root refcnt 2 bandwidth 100Mbit",
            "fq_codel": "qdisc fq_codel 0: root refcnt 2 limit 10240p",
            "fq": "qdisc fq 0: root refcnt 2 limit 10000p",
            "mq": "qdisc mq 0: root",
            "noqueue": "qdisc noqueue 0: root refcnt 2",
        }
        for kind, output in cases.items():
            with self.subTest(kind=kind):
                runner = FakeRunner()
                runner.qdisc["eth0"] = output
                optimizer = self.make_optimizer(runner, FakeProbe(measurement()))
                await optimizer.optimize(network("eth0", "ethernet"))
                self.assertEqual(runner.replaced(), [])

    async def test_custom_qdisc_is_preserved(self):
        runner = FakeRunner()
        runner.qdisc["eth0"] = "qdisc htb 1: root refcnt 2 r2q 10"
        optimizer = self.make_optimizer(runner, FakeProbe(measurement()))
        status = await optimizer.optimize(network("eth0", "ethernet"))
        self.assertIn("Custom qdisc", " ".join(status["skipped"]))
        self.assertEqual(runner.replaced(), [])

    async def test_virtual_interfaces_are_never_probed_or_changed(self):
        for iface, link_type in (("lo", ""), ("veth123", "ethernet"),
                                 ("docker0", "ethernet"), ("wg0", "vpn")):
            with self.subTest(interface=iface):
                runner = FakeRunner()
                probe = FakeProbe(measurement())
                optimizer = self.make_optimizer(runner, probe)
                status = await optimizer.optimize(network(iface, link_type))
                self.assertEqual(status["state"], "unsupported")
                self.assertEqual(runner.calls, [])
                self.assertEqual(probe.calls, [])

    async def test_cake_candidate_appears_only_when_the_module_exists(self):
        for available in (True, False):
            with self.subTest(sch_cake=available):
                runner = FakeRunner()
                runner.power["wlan0"] = "off"
                runner.qdisc["eth0"] = "qdisc pfifo 0: root refcnt 2 limit 1000p"
                optimizer = self.make_optimizer(
                    runner, StateProbe(runner, {}, measurement(30, 6)))

                async def cake_probe(_self=None, _value=available):
                    return _value

                optimizer._cake_available = cake_probe
                status = await optimizer.optimize(network("eth0", "ethernet"))
                keys = {item["key"] for item in status["candidates"]}
                self.assertEqual("qdisc-cake" in keys, available)
                if not available:
                    self.assertIn("sch_cake", " ".join(status["skipped"]))

    async def test_budget_stops_the_scan_without_leaving_changes(self):
        runner = FakeRunner()
        runner.qdisc["wlan0"] = "qdisc pfifo 0: root refcnt 2 limit 1000p"
        directory = self.temp_dir()
        optimizer = LatencyOptimizer(
            runner=runner, which_fn=runner.which,
            probe=StateProbe(runner, {}, measurement(30, 6)),
            state_path=os.path.join(directory, "latency.json"),
            profile_path=os.path.join(directory, "profiles.json"),
            budget_seconds=-1.0)          # bütçe daha başlarken dolmuş
        status = await optimizer.optimize(network())
        self.assertIn("Süre bütçesi doldu", " ".join(status["skipped"]))
        self.assertEqual(status["state"], "no-gain")
        self.assertEqual(runner.power["wlan0"], "on")
        self.assertEqual(runner.qdisc["wlan0"],
                         "qdisc pfifo 0: root refcnt 2 limit 1000p")

    async def test_wifi_and_ethernet_get_different_candidate_sets(self):
        wifi_runner = FakeRunner()
        wifi_runner.qdisc["wlan0"] = "qdisc pfifo 0: root refcnt 2 limit 1000p"
        wifi = self.make_optimizer(wifi_runner, StateProbe(
            wifi_runner, {}, measurement(30, 6)))
        wifi_status = await wifi.optimize(network())
        wifi_keys = {item["key"] for item in wifi_status["candidates"]}

        eth_runner = FakeRunner()
        eth_runner.qdisc["eth0"] = "qdisc pfifo 0: root refcnt 2 limit 1000p"
        eth_runner.set_ethernet("eth0")
        eth = self.make_optimizer(eth_runner, StateProbe(
            eth_runner, {}, measurement(30, 6)))
        eth_status = await eth.optimize(network("eth0", "ethernet"))
        eth_keys = {item["key"] for item in eth_status["candidates"]}

        self.assertIn("wifi-power-save", wifi_keys)
        self.assertNotIn("eee-off", wifi_keys)
        self.assertNotIn("rx-coalesce", wifi_keys)
        self.assertIn("eee-off", eth_keys)
        self.assertIn("rx-coalesce", eth_keys)
        self.assertNotIn("wifi-power-save", eth_keys)


class TestCandidateSelection(OptimizerCase):
    """Aday karşılaştırması: en iyi doğrulanmış aday seçilmeli."""

    def wifi_runner(self) -> FakeRunner:
        runner = FakeRunner()
        runner.qdisc["wlan0"] = "qdisc pfifo 0: root refcnt 2 limit 1000p"
        return runner

    async def test_single_better_candidate_is_chosen(self):
        runner = self.wifi_runner()
        runner.fail_qdisc_kinds = {"fq_codel", "fq", "cake"}
        probe = StateProbe(runner, {
            ("off", None, None, None): measurement(20, 2),
        }, measurement(30, 6))
        optimizer = self.make_optimizer(runner, probe)
        status = await optimizer.optimize(network())
        self.assertEqual(status["state"], "active")
        self.assertEqual(status["best"], "wifi-power-save")
        self.assertEqual(runner.power["wlan0"], "off")

    async def test_better_candidate_beats_weaker_one(self):
        runner = self.wifi_runner()
        probe = StateProbe(runner, {
            ("off", "pfifo", None, None): measurement(27, 5),   # zayıf kazanç
            ("on", "fq_codel", None, None): measurement(20, 2),  # güçlü kazanç
            ("off", "fq_codel", None, None): measurement(26, 5),
            ("on", "fq", None, None): measurement(31, 7),
            ("off", "fq", None, None): measurement(31, 7),
        }, measurement(31, 7))
        optimizer = self.make_optimizer(runner, probe)
        status = await optimizer.optimize(network())
        self.assertEqual(status["state"], "active")
        self.assertEqual(status["best"], "qdisc-fq_codel")
        self.assertEqual(runner.power["wlan0"], "on")
        self.assertTrue(runner.qdisc["wlan0"].startswith("qdisc fq_codel"))

    async def test_combination_wins_when_both_help(self):
        runner = self.wifi_runner()
        probe = StateProbe(runner, {
            ("off", "pfifo", None, None): measurement(26, 4),
            ("on", "fq_codel", None, None): measurement(27, 5),
            ("off", "fq_codel", None, None): measurement(20, 2),
            ("on", "fq", None, None): measurement(30, 6),
            ("off", "fq", None, None): measurement(30, 6),
        }, measurement(30, 6))
        optimizer = self.make_optimizer(runner, probe)
        status = await optimizer.optimize(network())
        self.assertEqual(status["state"], "active")
        self.assertEqual(status["best"], "wifi-power-save+qdisc-fq_codel")
        self.assertEqual(sorted(status["applied"]),
                         ["Wi-Fi güç tasarrufu kapatıldı", "fq_codel uygulandı"])

    async def test_no_candidate_helps_rolls_back_to_baseline(self):
        runner = self.wifi_runner()
        probe = StateProbe(runner, {}, measurement(30, 6))   # her durum aynı
        optimizer = self.make_optimizer(runner, probe)
        status = await optimizer.optimize(network())
        self.assertEqual(status["state"], "no-gain")
        self.assertFalse(status["active"])
        self.assertEqual(status["applied"], [])
        self.assertEqual(runner.power["wlan0"], "on")
        self.assertEqual(runner.qdisc["wlan0"],
                         "qdisc pfifo 0: root refcnt 2 limit 1000p")
        self.assertFalse(os.path.exists(optimizer.state_path))

    async def test_candidate_with_packet_loss_is_rejected(self):
        runner = self.wifi_runner()
        runner.fail_qdisc_kinds = {"fq_codel", "fq", "cake"}
        probe = StateProbe(runner, {
            ("off", None, None, None): measurement(18, 2, loss=12),
        }, measurement(30, 6, loss=0))
        optimizer = self.make_optimizer(runner, probe)
        status = await optimizer.optimize(network())
        self.assertEqual(status["state"], "no-gain")
        self.assertEqual(runner.power["wlan0"], "on")
        verdicts = " ".join(item["verdict"] for item in status["candidates"])
        self.assertIn("Paket kaybı", verdicts)

    async def test_candidate_with_worse_jitter_is_rejected(self):
        runner = self.wifi_runner()
        runner.fail_qdisc_kinds = {"fq_codel", "fq", "cake"}
        probe = StateProbe(runner, {
            ("off", None, None, None): measurement(29, 14),
        }, measurement(30, 6))
        optimizer = self.make_optimizer(runner, probe)
        status = await optimizer.optimize(network())
        self.assertEqual(status["state"], "no-gain")
        self.assertEqual(runner.power["wlan0"], "on")
        verdicts = " ".join(item["verdict"] for item in status["candidates"])
        self.assertIn("kötüleşti", verdicts)

    async def test_candidate_with_worse_p95_is_rejected(self):
        runner = self.wifi_runner()
        runner.fail_qdisc_kinds = {"fq_codel", "fq", "cake"}
        probe = StateProbe(runner, {
            ("off", None, None, None): measurement(29, 6, p95=70),
        }, measurement(30, 6, p95=34))
        optimizer = self.make_optimizer(runner, probe)
        status = await optimizer.optimize(network())
        self.assertEqual(status["state"], "no-gain")
        self.assertEqual(runner.power["wlan0"], "on")

    async def test_connection_loss_during_candidate_is_rejected(self):
        runner = self.wifi_runner()
        runner.fail_qdisc_kinds = {"fq_codel", "fq", "cake"}
        probe = StateProbe(runner, {
            ("off", None, None, None): measurement(connected=False),
        }, measurement(30, 6))
        optimizer = self.make_optimizer(runner, probe)
        status = await optimizer.optimize(network())
        self.assertEqual(status["state"], "no-gain")
        self.assertEqual(runner.power["wlan0"], "on")

    async def test_final_verification_must_repeat_the_gain(self):
        """Tek ölçümlük kazanç yeterli değil; son doğrulama tekrarlamalı."""
        runner = self.wifi_runner()
        runner.fail_qdisc_kinds = {"fq_codel", "fq", "cake"}
        sequence = [measurement(30, 6),     # taban
                    measurement(20, 2),     # aday ölçümü — kazanç var
                    measurement(30, 6)]     # son doğrulama — kazanç yok
        optimizer = self.make_optimizer(runner, FakeProbe(*sequence))
        status = await optimizer.optimize(network())
        self.assertEqual(status["state"], "no-gain")
        self.assertIn("tekrarlanmadı", status["message"])
        self.assertEqual(runner.power["wlan0"], "on")
        self.assertFalse(os.path.exists(optimizer.state_path))

    async def test_failed_final_rollback_is_reported_as_a_rollback_failure(self):
        """Son doğrulama başarısız + geri alma da başarısız → 'kazanç yok' deme."""
        runner = self.wifi_runner()
        runner.fail_qdisc_kinds = {"fq_codel", "fq", "cake"}
        sequence = [measurement(30, 6), measurement(20, 2), measurement(30, 6)]
        optimizer = self.make_optimizer(runner, FakeProbe(*sequence))
        original_restore = optimizer._restore_action
        state = {"final": False}

        async def restore(action):
            if state["final"]:
                return False
            return await original_restore(action)

        optimizer._restore_action = restore
        original_best = optimizer._best

        def best(results):
            state["final"] = True     # yalnız son doğrulamadan sonrası patlasın
            return original_best(results)

        optimizer._best = best
        status = await optimizer.optimize(network())
        self.assertEqual(status["state"], "rollback-failed")
        self.assertTrue(status["active"])
        self.assertIn("geri alınamadı", status["message"])

    async def test_ethernet_eee_candidate_is_measured_and_kept(self):
        runner = FakeRunner()
        runner.qdisc["eth0"] = "qdisc fq_codel 0: root refcnt 2 limit 10240p"
        runner.set_ethernet("eth0", eee="enabled", adaptive_rx="off",
                            rx_usecs="0")
        probe = StateProbe(runner, {
            (None, None, "disabled", None): measurement(20, 2),
        }, measurement(30, 6))
        optimizer = self.make_optimizer(runner, probe)
        status = await optimizer.optimize(network("eth0", "ethernet"))
        self.assertEqual(status["state"], "active")
        self.assertEqual(status["best"], "eee-off")
        self.assertEqual(runner.eee["eth0"], "disabled")

    async def test_ethernet_coalesce_candidate_is_rolled_back_when_useless(self):
        runner = FakeRunner()
        runner.qdisc["eth0"] = "qdisc fq_codel 0: root refcnt 2 limit 10240p"
        runner.set_ethernet("eth0", eee="disabled", adaptive_rx="on",
                            rx_usecs="50")
        probe = StateProbe(runner, {}, measurement(30, 6))
        optimizer = self.make_optimizer(runner, probe)
        status = await optimizer.optimize(network("eth0", "ethernet"))
        self.assertEqual(status["state"], "no-gain")
        self.assertEqual(runner.coalesce["eth0"],
                         {"adaptive-rx": "on", "rx-usecs": "50",
                          "rx-frames": "0"})


class TestLatencyRollback(OptimizerCase):
    async def test_wifi_power_save_snapshot_and_disable_restore(self):
        runner = FakeRunner()
        runner.fail_qdisc_kinds = {"fq_codel", "fq", "cake"}
        probe = StateProbe(runner, {
            ("off", None, None, None): measurement(20, 2),
        }, measurement(25, 5))
        optimizer = self.make_optimizer(runner, probe)
        status = await optimizer.optimize(network())
        self.assertTrue(status["active"])
        self.assertEqual(runner.power["wlan0"], "off")
        self.assertTrue(os.path.exists(optimizer.state_path))

        self.assertTrue(await optimizer.disable())
        self.assertEqual(runner.power["wlan0"], "on")
        self.assertFalse(os.path.exists(optimizer.state_path))

    async def test_simple_fifo_becomes_fq_codel_then_restores(self):
        runner = FakeRunner()
        runner.power["wlan0"] = "off"
        runner.qdisc["eth0"] = "qdisc pfifo 0: root refcnt 2 limit 1000p"
        probe = StateProbe(runner, {
            (None, "fq_codel", None, None): measurement(24, 2),
        }, measurement(30, 5))
        optimizer = self.make_optimizer(runner, probe)
        status = await optimizer.optimize(network("eth0", "ethernet"))
        self.assertTrue(status["active"])
        self.assertIn("fq_codel uygulandı", status["applied"])

        await optimizer.disable()
        self.assertIn(
            ["tc", "qdisc", "replace", "dev", "eth0", "root",
             "pfifo", "limit", "1000p"], runner.calls)
        self.assertEqual(runner.qdisc["eth0"],
                         "qdisc pfifo 0: root refcnt 2 limit 1000p")

    async def test_pfifo_fast_is_restored_without_unsupported_options(self):
        """tc, pfifo_fast için seçenek ayrıştırmaz.

        ``tc qdisc replace … root pfifo_fast bands 3 priomap …`` gerçek
        sistemde şu hatayı verir::

            qdisc 'pfifo_fast' does not support option parsing

        Görülen bands/priomap değerleri çekirdek sabitidir. Bunları geri
        yazma komutuna koymak, geri almanın HER SEFERİNDE başarısız olması
        ve arayüzün fq_codel'de takılı kalması demektir.
        """
        runner = FakeRunner()
        runner.power["wlan0"] = "off"
        runner.qdisc["eth0"] = (
            "qdisc pfifo_fast 0: root refcnt 2 bands 3 priomap "
            "1 2 2 2 1 2 0 0 1 1 1 1 1 1 1 1")
        probe = StateProbe(runner, {
            (None, "fq_codel", None, None): measurement(24, 2),
        }, measurement(30, 5))
        optimizer = self.make_optimizer(runner, probe)
        status = await optimizer.optimize(network("eth0", "ethernet"))
        self.assertTrue(status["active"])

        self.assertTrue(await optimizer.disable())
        restore = [call for call in runner.calls
                   if call[:6] == ["tc", "qdisc", "replace", "dev",
                                   "eth0", "root"]]
        self.assertEqual(
            restore[-1],
            ["tc", "qdisc", "replace", "dev", "eth0", "root", "pfifo_fast"])
        self.assertTrue(runner.qdisc["eth0"].startswith("qdisc pfifo_fast"))

    def test_pfifo_fast_recipe_carries_no_options(self):
        baseline, note = LatencyOptimizer._qdisc_baseline(
            "qdisc pfifo_fast 0: root refcnt 2 bands 3 priomap "
            "1 2 2 2 1 2 0 0 1 1 1 1 1 1 1 1")
        self.assertEqual(note, "")
        self.assertEqual(baseline, ("pfifo_fast", ["pfifo_fast"]))

    def test_fifo_limit_is_kept_in_the_recipe(self):
        for output, expected in (
            ("qdisc pfifo 0: root refcnt 2 limit 1000p",
             ("pfifo", ["pfifo", "limit", "1000p"])),
            ("qdisc bfifo 0: root refcnt 2 limit 10000b",
             ("bfifo", ["bfifo", "limit", "10000b"])),
            ("qdisc pfifo 8001: root refcnt 2 limit 1000p",
             ("pfifo", ["handle", "8001:", "pfifo", "limit", "1000p"])),
        ):
            with self.subTest(output=output):
                self.assertEqual(
                    LatencyOptimizer._qdisc_baseline(output)[0], expected)

    async def test_half_applied_candidate_rolls_everything_back(self):
        """Birleşik adayın ikinci adımı patlarsa ilk adım da geri alınmalı."""
        runner = FakeRunner()
        runner.qdisc["wlan0"] = "qdisc pfifo 0: root refcnt 2 limit 1000p"
        probe = StateProbe(runner, {
            ("off", "pfifo", None, None): measurement(26, 4),
            ("on", "fq_codel", None, None): measurement(26, 4),
            ("off", "fq_codel", None, None): measurement(20, 2),
        }, measurement(30, 6))
        optimizer = self.make_optimizer(runner, probe)
        # Birleşik aday (wifi + fq_codel) uygulanırken fq_codel patlar.
        original_run = optimizer._run_step
        state = {"seen": 0}

        async def failing_run(step, env):
            if step.kind == "qdisc" and state["seen"] == 0 and \
                    runner.power.get(env.interface) == "off":
                state["seen"] = 1
                raise __import__("dpibypass.latency", fromlist=["LatencyError"]) \
                    .LatencyError("fq_codel uygulanamadı")
            return await original_run(step, env)

        optimizer._run_step = failing_run
        status = await optimizer.optimize(network())
        # Yarım kalan aday atlanır; hiçbir ayar yarım bırakılmaz.
        self.assertEqual(runner.power["wlan0"], "off" if status["active"] else "on")
        if not status["active"]:
            self.assertEqual(runner.qdisc["wlan0"],
                             "qdisc pfifo 0: root refcnt 2 limit 1000p")
        verdicts = " ".join(item["verdict"] for item in status["candidates"])
        self.assertIn("uygulanamadı", verdicts)

    async def test_apply_failure_restores_snapshot_and_clears_state(self):
        runner = FakeRunner()
        runner.qdisc["wlan0"] = "qdisc pfifo 0: root refcnt 2 limit 1000p"
        runner.fail_fq_codel_once = True
        probe = StateProbe(runner, {}, measurement(30, 6))
        optimizer = self.make_optimizer(runner, probe)
        status = await optimizer.optimize(network())
        self.assertEqual(status["state"], "no-gain")
        self.assertEqual(runner.power["wlan0"], "on")
        self.assertEqual(runner.qdisc["wlan0"],
                         "qdisc pfifo 0: root refcnt 2 limit 1000p")
        self.assertFalse(os.path.exists(optimizer.state_path))

    async def test_packet_loss_increase_rolls_back(self):
        runner = FakeRunner()
        runner.power["wlan0"] = "off"
        runner.qdisc["eth0"] = "qdisc bfifo 0: root refcnt 2 limit 10000b"
        probe = StateProbe(runner, {
            (None, "fq_codel", None, None): measurement(20, 2, loss=20),
            (None, "fq", None, None): measurement(20, 2, loss=20),
            (None, "cake", None, None): measurement(20, 2, loss=20),
        }, measurement(25, 4, loss=0))
        optimizer = self.make_optimizer(runner, probe)
        status = await optimizer.optimize(network("eth0", "ethernet"))
        self.assertEqual(status["state"], "no-gain")
        self.assertEqual(runner.qdisc["eth0"],
                         "qdisc bfifo 0: root refcnt 2 limit 10000b")
        verdicts = " ".join(item["verdict"] for item in status["candidates"])
        self.assertIn("Paket kaybı", verdicts)

    async def test_connection_loss_rolls_back_immediately_after_measurement(self):
        runner = FakeRunner()
        runner.power["wlan0"] = "off"
        runner.qdisc["eth0"] = "qdisc pfifo 0: root refcnt 2 limit 1000p"
        probe = StateProbe(runner, {
            (None, "fq_codel", None, None): measurement(connected=False),
            (None, "fq", None, None): measurement(connected=False),
        }, measurement(25, 4))
        optimizer = self.make_optimizer(runner, probe)
        status = await optimizer.optimize(network("eth0", "ethernet"))
        self.assertEqual(status["state"], "no-gain")
        self.assertEqual(runner.qdisc["eth0"],
                         "qdisc pfifo 0: root refcnt 2 limit 1000p")

    async def test_baseline_without_connection_changes_nothing(self):
        runner = FakeRunner()
        runner.qdisc["eth0"] = "qdisc pfifo 0: root refcnt 2 limit 1000p"
        optimizer = self.make_optimizer(
            runner, FakeProbe(measurement(connected=False)))
        status = await optimizer.optimize(network("eth0", "ethernet"))
        self.assertEqual(status["state"], "failed")
        self.assertEqual(runner.replaced(), [])

    async def test_disable_is_idempotent(self):
        runner = FakeRunner()
        runner.fail_qdisc_kinds = {"fq_codel", "fq", "cake"}
        probe = StateProbe(runner, {
            ("off", None, None, None): measurement(20, 2),
        }, measurement(25, 5))
        optimizer = self.make_optimizer(runner, probe)
        await optimizer.optimize(network())
        self.assertTrue(await optimizer.disable())
        calls_after_first = len(runner.calls)
        self.assertTrue(await optimizer.disable())
        self.assertEqual(len(runner.calls), calls_after_first)

    async def test_cleanup_recovers_persisted_runtime_snapshot(self):
        runner = FakeRunner()
        runner.fail_qdisc_kinds = {"fq_codel", "fq", "cake"}
        directory = self.temp_dir()
        path = os.path.join(directory, "latency.json")
        probe = StateProbe(runner, {
            ("off", None, None, None): measurement(20, 2),
        }, measurement(25, 5))
        optimizer = LatencyOptimizer(
            runner=runner, which_fn=runner.which, probe=probe,
            state_path=path,
            profile_path=os.path.join(directory, "profiles.json"))
        await optimizer.optimize(network())
        self.assertEqual(runner.power["wlan0"], "off")

        # Servis çöktü, yeni süreç açıldı: dosyadaki tarif geri yüklenmeli.
        cleanup = LatencyOptimizer(
            runner=runner, which_fn=runner.which, state_path=path,
            profile_path=os.path.join(directory, "profiles.json"))
        self.assertTrue(cleanup.restore_persisted_sync())
        self.assertEqual(runner.power["wlan0"], "on")
        self.assertFalse(os.path.exists(path))

    async def test_crash_recovery_restores_multi_step_snapshot(self):
        runner = FakeRunner()
        runner.qdisc["eth0"] = "qdisc pfifo 0: root refcnt 2 limit 1000p"
        runner.set_ethernet("eth0", eee="enabled")
        directory = self.temp_dir()
        path = os.path.join(directory, "latency.json")
        probe = StateProbe(runner, {
            (None, "fq_codel", "disabled", None): measurement(20, 2),
            (None, "fq_codel", None, None): measurement(24, 3),
            (None, None, "disabled", None): measurement(24, 3),
        }, measurement(30, 6))
        optimizer = LatencyOptimizer(
            runner=runner, which_fn=runner.which, probe=probe, state_path=path,
            profile_path=os.path.join(directory, "profiles.json"))
        status = await optimizer.optimize(network("eth0", "ethernet"))
        self.assertTrue(status["active"])
        self.assertTrue(os.path.exists(path))

        recovered = LatencyOptimizer(
            runner=runner, which_fn=runner.which, state_path=path,
            profile_path=os.path.join(directory, "profiles.json"))
        self.assertTrue(await recovered.recover())
        self.assertEqual(runner.eee["eth0"], "enabled")
        self.assertEqual(runner.qdisc["eth0"],
                         "qdisc pfifo 0: root refcnt 2 limit 1000p")
        self.assertFalse(os.path.exists(path))

    async def test_legacy_snapshot_format_is_still_recoverable(self):
        """1.2.0'dan kalan tek eylemli /run dosyası da geri alınabilmeli."""
        runner = FakeRunner()
        directory = self.temp_dir()
        path = os.path.join(directory, "latency.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump({
                "interface": "wlan0", "link_type": "wifi",
                "wifi_power_save": "on",
                "qdisc": {"kind": "pfifo",
                          "restore_args": ["pfifo", "limit", "1000p"],
                          "applied_output": "qdisc fq_codel 0: root"},
            }, handle)
        runner.power["wlan0"] = "off"
        runner.qdisc["wlan0"] = "qdisc fq_codel 0: root"
        optimizer = LatencyOptimizer(
            runner=runner, which_fn=runner.which, state_path=path,
            profile_path=os.path.join(directory, "profiles.json"))
        self.assertTrue(await optimizer.recover())
        self.assertEqual(runner.power["wlan0"], "on")
        self.assertEqual(runner.qdisc["wlan0"],
                         "qdisc pfifo 0: root refcnt 2 limit 1000p")

    async def test_corrupt_snapshot_is_rejected(self):
        for payload in (
            {"interface": "../../etc", "link_type": "wifi", "actions": []},
            {"interface": "eth0", "link_type": "vpn", "actions": []},
            {"interface": "eth0", "link_type": "ethernet", "actions": [
                {"kind": "qdisc", "interface": "eth0",
                 "restore": {"kind": "htb", "args": ["htb"]}}]},
            {"interface": "eth0", "link_type": "ethernet", "actions": [
                {"kind": "qdisc", "interface": "eth0",
                 "restore": {"kind": "pfifo", "args": ["pfifo; rm -rf /"]}}]},
            {"interface": "eth0", "link_type": "ethernet", "actions": [
                {"kind": "coalesce", "interface": "eth0",
                 "restore": {"params": {"rx-usecs": "0; reboot"}}}]},
            {"interface": "eth0", "link_type": "ethernet", "actions": [
                {"kind": "sysctl", "interface": "eth0",
                 "restore": {"value": "1"}}]},
        ):
            with self.subTest(payload=payload):
                with self.assertRaises(ValueError):
                    LatencySnapshot.from_dict(payload)

    async def test_failed_rollback_is_reported_not_hidden(self):
        """Geri alma başarısızsa 'her şey yolunda' denmez."""
        runner = FakeRunner()
        runner.fail_qdisc_kinds = {"fq_codel", "fq", "cake"}
        probe = StateProbe(runner, {
            ("off", None, None, None): measurement(20, 2),
        }, measurement(30, 6))
        optimizer = self.make_optimizer(runner, probe)
        status = await optimizer.optimize(network())
        self.assertTrue(status["active"])

        # iw artık yok: güç tasarrufu geri yüklenemez.
        runner.tools.discard("iw")
        self.assertFalse(await optimizer.disable())
        self.assertEqual(optimizer.status.state, "rollback-failed")
        self.assertTrue(optimizer.status.active)
        self.assertTrue(os.path.exists(optimizer.state_path))

    async def test_disable_after_failed_rollback_still_retries(self):
        runner = FakeRunner()
        runner.fail_qdisc_kinds = {"fq_codel", "fq", "cake"}
        probe = StateProbe(runner, {
            ("off", None, None, None): measurement(20, 2),
        }, measurement(30, 6))
        optimizer = self.make_optimizer(runner, probe)
        await optimizer.optimize(network())
        runner.tools.discard("iw")
        self.assertFalse(await optimizer.disable())
        runner.tools.add("iw")
        self.assertTrue(await optimizer.disable())
        self.assertEqual(runner.power["wlan0"], "on")
        self.assertFalse(os.path.exists(optimizer.state_path))

    async def test_user_qdisc_change_is_not_overwritten_on_disable(self):
        runner = FakeRunner()
        runner.power["wlan0"] = "off"
        runner.qdisc["eth0"] = "qdisc pfifo 0: root refcnt 2 limit 1000p"
        probe = StateProbe(runner, {
            (None, "fq_codel", None, None): measurement(24, 2),
        }, measurement(30, 5))
        optimizer = self.make_optimizer(runner, probe)
        await optimizer.optimize(network("eth0", "ethernet"))

        # Kullanıcı araya girip kendi qdisc'ini kurdu.
        runner.qdisc["eth0"] = "qdisc htb 1: root refcnt 2 r2q 10"
        self.assertTrue(await optimizer.disable())
        self.assertEqual(runner.qdisc["eth0"],
                         "qdisc htb 1: root refcnt 2 r2q 10")

    async def test_external_qdisc_change_stops_the_benchmark(self):
        """Tarama sırasında dışarıdan değişiklik olursa devam edilmez."""
        runner = FakeRunner()
        runner.power["wlan0"] = "off"
        runner.qdisc["eth0"] = "qdisc pfifo 0: root refcnt 2 limit 1000p"
        probe = StateProbe(runner, {}, measurement(30, 6))
        original = probe.measure
        calls = {"count": 0}

        def measure(interface, gateway):
            calls["count"] += 1
            result = original(interface, gateway)
            if calls["count"] == 2:
                # İlk aday ölçülürken başka bir program qdisc'i değiştirsin;
                # geri alma bunu görüp kullanıcının ayarını korumalı.
                runner.qdisc["eth0"] = "qdisc htb 1: root refcnt 2 r2q 10"
            return result

        probe.measure = measure
        optimizer = self.make_optimizer(runner, probe)
        status = await optimizer.optimize(network("eth0", "ethernet"))
        self.assertEqual(status["state"], "external-change")
        self.assertFalse(status["active"])
        self.assertEqual(runner.qdisc["eth0"],
                         "qdisc htb 1: root refcnt 2 r2q 10")

    async def test_external_coalesce_change_is_preserved(self):
        runner = FakeRunner()
        runner.qdisc["eth0"] = "qdisc fq_codel 0: root refcnt 2 limit 10240p"
        runner.set_ethernet("eth0", eee="disabled", adaptive_rx="on",
                            rx_usecs="50")
        probe = StateProbe(runner, {}, measurement(30, 6))
        original = probe.measure
        calls = {"count": 0}

        def measure(interface, gateway):
            calls["count"] += 1
            result = original(interface, gateway)
            if calls["count"] == 2:
                runner.coalesce["eth0"]["rx-usecs"] = "123"
            return result

        probe.measure = measure
        optimizer = self.make_optimizer(runner, probe)
        await optimizer.optimize(network("eth0", "ethernet"))
        self.assertEqual(runner.coalesce["eth0"]["rx-usecs"], "123")


class TestPerNetworkLearning(OptimizerCase):
    def wifi_setup(self):
        runner = FakeRunner()
        runner.qdisc["wlan0"] = "qdisc pfifo 0: root refcnt 2 limit 1000p"
        table = {
            ("off", "pfifo", None, None): measurement(26, 4),
            ("on", "fq_codel", None, None): measurement(27, 5),
            ("off", "fq_codel", None, None): measurement(20, 2),
            ("on", "fq", None, None): measurement(30, 6),
            ("off", "fq", None, None): measurement(30, 6),
        }
        return runner, table

    async def test_best_candidate_is_cached_per_network(self):
        runner, table = self.wifi_setup()
        directory = self.temp_dir()
        optimizer = self.make_optimizer(
            runner, StateProbe(runner, table, measurement(30, 6)), directory)
        status = await optimizer.optimize(network())
        self.assertEqual(status["state"], "active")

        stored = LatencyProfiles(os.path.join(directory, "profiles.json"))
        entry = stored.get(network().key)
        self.assertIsNotNone(entry)
        self.assertEqual(entry["candidate"], status["best"])

    async def test_cached_candidate_skips_the_full_benchmark(self):
        runner, table = self.wifi_setup()
        directory = self.temp_dir()
        first_probe = StateProbe(runner, table, measurement(30, 6))
        optimizer = self.make_optimizer(runner, first_probe, directory)
        await optimizer.optimize(network())
        await optimizer.disable()
        full_run_measurements = len(first_probe.calls)

        runner2, _ = self.wifi_setup()
        second_probe = StateProbe(runner2, table, measurement(30, 6))
        optimizer2 = self.make_optimizer(runner2, second_probe, directory)
        status = await optimizer2.optimize(network())

        self.assertEqual(status["state"], "active")
        self.assertTrue(status["cached"])
        self.assertEqual(len(status["candidates"]), 1)
        self.assertLess(len(second_probe.calls), full_run_measurements)
        self.assertEqual(runner2.power["wlan0"], "off")

    async def test_cached_candidate_that_no_longer_helps_is_rebenchmarked(self):
        runner, table = self.wifi_setup()
        directory = self.temp_dir()
        optimizer = self.make_optimizer(
            runner, StateProbe(runner, table, measurement(30, 6)), directory)
        await optimizer.optimize(network())
        await optimizer.disable()

        # Aynı ağ, ama kayıtlı aday artık kötüleştiriyor.
        runner2, _ = self.wifi_setup()
        bad = {("off", "fq_codel", None, None): measurement(40, 12)}
        probe2 = StateProbe(runner2, bad, measurement(20, 2))
        optimizer2 = self.make_optimizer(runner2, probe2, directory)
        status = await optimizer2.optimize(network())

        self.assertEqual(status["state"], "no-gain")
        self.assertFalse(status["active"])
        self.assertGreater(len(status["candidates"]), 1)   # yeniden tarandı
        self.assertEqual(runner2.power["wlan0"], "on")
        self.assertEqual(runner2.qdisc["wlan0"],
                         "qdisc pfifo 0: root refcnt 2 limit 1000p")
        stored = LatencyProfiles(os.path.join(directory, "profiles.json"))
        self.assertIsNone(stored.get(network().key))

    async def test_cached_candidate_for_missing_hardware_is_dropped(self):
        directory = self.temp_dir()
        profiles = LatencyProfiles(os.path.join(directory, "profiles.json"))
        profiles.remember(network().key, "eee-off", "EEE", "wlan0", {})

        runner, table = self.wifi_setup()
        optimizer = self.make_optimizer(
            runner, StateProbe(runner, table, measurement(30, 6)), directory)
        status = await optimizer.optimize(network())
        self.assertEqual(status["state"], "active")
        self.assertFalse(status["cached"])

    async def test_different_networks_keep_separate_profiles(self):
        runner, table = self.wifi_setup()
        directory = self.temp_dir()
        optimizer = self.make_optimizer(
            runner, StateProbe(runner, table, measurement(30, 6)), directory)
        await optimizer.optimize(network(ssid="Ev"))
        await optimizer.disable()

        stored = LatencyProfiles(os.path.join(directory, "profiles.json"))
        self.assertIsNotNone(stored.get(network(ssid="Ev").key))
        self.assertIsNone(stored.get(network(ssid="Ofis").key))


class TestLatencyNetworkChange(OptimizerCase):
    async def test_old_interface_restored_before_new_interface_apply(self):
        from dpibypass.daemon import Daemon

        runner = FakeRunner()
        runner.power["wlan0"] = "off"
        runner.qdisc["eth0"] = "qdisc pfifo 0: root refcnt 2 limit 1000p"
        runner.qdisc["eth1"] = "qdisc pfifo 0: root refcnt 2 limit 1000p"
        probe = StateProbe(runner, {
            (None, "fq_codel", None, None): measurement(22, 2),
        }, measurement(30, 5))
        optimizer = self.make_optimizer(runner, probe)
        daemon = Daemon.__new__(Daemon)
        daemon.config = {"latency_mode": True}
        daemon.latency = optimizer
        daemon._latency_control_lock = asyncio.Lock()
        daemon._latency_task = asyncio.create_task(
            optimizer.optimize(network("eth0", "ethernet")))
        await daemon._latency_task

        await daemon._restart_latency(network("eth1", "ethernet"))
        await daemon._latency_task

        restore_old = runner.calls.index(
            ["tc", "qdisc", "replace", "dev", "eth0", "root",
             "pfifo", "limit", "1000p"])
        apply_new = runner.calls.index(
            ["tc", "qdisc", "replace", "dev", "eth1", "root", "fq_codel"])
        self.assertLess(restore_old, apply_new)

    async def test_cancelled_run_restores_the_old_interface(self):
        runner = FakeRunner()
        runner.power["wlan0"] = "off"
        runner.qdisc["eth0"] = "qdisc pfifo 0: root refcnt 2 limit 1000p"
        probe = StateProbe(runner, {
            (None, "fq_codel", None, None): measurement(22, 2),
        }, measurement(30, 5))
        optimizer = self.make_optimizer(runner, probe)
        original = probe.measure
        calls = {"count": 0}

        def measure(interface, gateway):
            calls["count"] += 1
            if calls["count"] == 2:      # ilk aday ölçülürken ağ değişti
                optimizer.request_cancel()
            return original(interface, gateway)

        probe.measure = measure
        status = await optimizer.optimize(network("eth0", "ethernet"))
        self.assertIn(status["state"], ("rolled-back", "cancelled"))
        self.assertEqual(runner.qdisc["eth0"],
                         "qdisc pfifo 0: root refcnt 2 limit 1000p")
        self.assertFalse(os.path.exists(optimizer.state_path))


class TestLatencyIsolation(OptimizerCase):
    async def test_no_vodafone_firewall_or_ipv6_commands(self):
        runner = FakeRunner()
        runner.qdisc["wlan0"] = "qdisc pfifo 0: root refcnt 2 limit 1000p"
        probe = StateProbe(runner, {
            ("off", "fq_codel", None, None): measurement(20, 2),
        }, measurement(30, 6))
        optimizer = self.make_optimizer(runner, probe)
        await optimizer.optimize(network())
        forbidden = {"nft", "iptables", "ip6tables", "sysctl", "ip", "nmcli",
                     "resolvectl", "systemd-resolve"}
        self.assertFalse(any(call and call[0] in forbidden
                             for call in runner.calls))

    async def test_only_reversible_commands_are_used(self):
        """Yalnızca okunup geri yazılabilen komut biçimleri kullanılmalı."""
        runner = FakeRunner()
        runner.qdisc["eth0"] = "qdisc pfifo 0: root refcnt 2 limit 1000p"
        runner.set_ethernet("eth0")
        probe = StateProbe(runner, {}, measurement(30, 6))
        optimizer = self.make_optimizer(runner, probe)
        await optimizer.optimize(network("eth0", "ethernet"))
        allowed = {"tc", "ethtool", "iw", "modinfo"}
        self.assertTrue(all(call[0] in allowed for call in runner.calls),
                        f"beklenmeyen komut: {runner.calls}")

    async def test_status_serialization_contains_measurements(self):
        runner = FakeRunner()
        runner.fail_qdisc_kinds = {"fq_codel", "fq", "cake"}
        probe = StateProbe(runner, {
            ("off", None, None, None): measurement(20, 2),
        }, measurement(25, 5))
        optimizer = self.make_optimizer(runner, probe)
        data = await optimizer.optimize(network())
        self.assertEqual(set(data), {
            "enabled", "active", "interface", "state", "message",
            "before", "after", "applied", "skipped", "candidates", "best",
            "cached", "gain",
        })
        self.assertEqual(data["before"]["remote"]["median_ms"], 25)
        self.assertEqual(data["after"]["remote"]["median_ms"], 20)
        self.assertTrue(data["active"])
        self.assertEqual(data["gain"]["median_ms"], -5)
        self.assertTrue(json.dumps(data))       # IPC üzerinden taşınabilir

    async def test_no_gain_status_reports_no_fake_success(self):
        runner = FakeRunner()
        runner.qdisc["wlan0"] = "qdisc pfifo 0: root refcnt 2 limit 1000p"
        probe = StateProbe(runner, {}, measurement(30, 6))
        optimizer = self.make_optimizer(runner, probe)
        data = await optimizer.optimize(network())
        self.assertFalse(data["active"])
        self.assertEqual(data["applied"], [])
        self.assertEqual(data["gain"], {})
        self.assertIn("bulunamadı", data["message"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
