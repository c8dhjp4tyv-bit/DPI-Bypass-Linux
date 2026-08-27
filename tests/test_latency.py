"""Ping düşürme kipinin ağdan ve root yetkisinden bağımsız testleri."""

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
                               LatencyProbe, LatencyStats)
from dpibypass.netmon import NetworkFingerprint  # noqa: E402


def network(interface: str = "wlan0", link_type: str = "wifi",
            gateway: str = "192.0.2.1") -> NetworkFingerprint:
    return NetworkFingerprint(interface=interface, gateway=gateway,
                              link_type=link_type, ssid="Test")


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
        packet_loss=loss if connected else 100.0,
    )
    gateway = LatencyStats(
        sent=5, received=5, median_ms=2.0, minimum_ms=1.0,
        p95_ms=3.0, jitter_ms=0.5, packet_loss=0.0)
    return LatencyMeasurement("icmp", gateway, remote,
                              ["192.0.2.1", "1.1.1.1"])


class FakeProbe:
    def __init__(self, *results: LatencyMeasurement) -> None:
        self.results = list(results)
        self.calls: list[tuple[str, str]] = []

    def measure(self, interface: str, gateway: str) -> LatencyMeasurement:
        self.calls.append((interface, gateway))
        if not self.results:
            raise AssertionError("Beklenmeyen ek ölçüm")
        return self.results.pop(0)


class FakeRunner:
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
        self.fail_fq_codel_once = False

    def which(self, name: str) -> str | None:
        return f"/usr/sbin/{name}" if name in self.tools else None

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
            kind_index = 1 if args[:1] == ["handle"] else 0
            if kind_index:
                kind_index = 2
            kind = args[kind_index]
            self.qdisc[iface] = f"qdisc {kind} 0: root"
            return subprocess.CompletedProcess(cmd, 0, "", "")
        return subprocess.CompletedProcess(cmd, 0, "", "")


class OptimizerCase(unittest.IsolatedAsyncioTestCase):
    def make_optimizer(self, runner: FakeRunner,
                       probe: FakeProbe) -> LatencyOptimizer:
        directory = tempfile.TemporaryDirectory(prefix="dpibypass-latency-")
        self.addCleanup(directory.cleanup)
        return LatencyOptimizer(
            runner=runner, which_fn=runner.which, probe=probe,
            state_path=os.path.join(directory.name, "latency.json"))


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
        self.assertEqual(stats.packet_loss, 20)

    def test_one_ms_noise_is_not_a_verified_gain(self):
        ok, message = LatencyOptimizer.evaluate(
            measurement(median=20, jitter=4),
            measurement(median=19, jitter=3.8))
        self.assertFalse(ok)
        self.assertIn("doğrulanmış", message)

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
                changes = [call for call in runner.calls
                           if call[:3] == ["tc", "qdisc", "replace"]]
                self.assertEqual(changes, [])

    async def test_custom_qdisc_is_preserved(self):
        runner = FakeRunner()
        runner.qdisc["eth0"] = "qdisc htb 1: root refcnt 2 r2q 10"
        optimizer = self.make_optimizer(runner, FakeProbe(measurement()))
        status = await optimizer.optimize(network("eth0", "ethernet"))
        self.assertIn("Custom qdisc", " ".join(status["skipped"]))
        self.assertFalse(any(call[:3] == ["tc", "qdisc", "replace"]
                             for call in runner.calls))

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


class TestLatencyRollback(OptimizerCase):
    async def test_wifi_power_save_snapshot_and_disable_restore(self):
        runner = FakeRunner()
        probe = FakeProbe(measurement(25, 5), measurement(20, 2))
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
        runner.qdisc["eth0"] = "qdisc pfifo 0: root refcnt 2 limit 1000p"
        optimizer = self.make_optimizer(
            runner, FakeProbe(measurement(30, 5), measurement(24, 2)))
        status = await optimizer.optimize(network("eth0", "ethernet"))
        self.assertTrue(status["active"])
        self.assertIn("fq_codel uygulandı", status["applied"])

        await optimizer.disable()
        self.assertIn(
            ["tc", "qdisc", "replace", "dev", "eth0", "root",
             "pfifo", "limit", "1000p"], runner.calls)

    async def test_pfifo_fast_restore_recipe_is_preserved(self):
        runner = FakeRunner()
        runner.qdisc["eth0"] = (
            "qdisc pfifo_fast 0: root refcnt 2 bands 3 priomap "
            "1 2 2 2 1 2 0 0 1 1 1 1 1 1 1 1")
        optimizer = self.make_optimizer(
            runner, FakeProbe(measurement(30, 5), measurement(24, 2)))
        await optimizer.optimize(network("eth0", "ethernet"))
        await optimizer.disable()
        restore = [call for call in runner.calls
                   if call[:6] == ["tc", "qdisc", "replace", "dev",
                                   "eth0", "root"]]
        self.assertIn("pfifo_fast", restore[-1])
        self.assertIn("priomap", restore[-1])

    async def test_half_applied_failure_rolls_everything_back(self):
        runner = FakeRunner()
        runner.qdisc["wlan0"] = "qdisc pfifo 0: root refcnt 2 limit 1000p"
        runner.fail_fq_codel_once = True
        optimizer = self.make_optimizer(runner, FakeProbe(measurement()))
        status = await optimizer.optimize(network())
        self.assertEqual(status["state"], "rolled-back")
        self.assertEqual(runner.power["wlan0"], "on")
        self.assertFalse(os.path.exists(optimizer.state_path))

    async def test_packet_loss_increase_rolls_back(self):
        runner = FakeRunner()
        runner.qdisc["eth0"] = "qdisc bfifo 0: root refcnt 2 limit 10000b"
        optimizer = self.make_optimizer(
            runner, FakeProbe(measurement(25, 4, loss=0),
                              measurement(20, 2, loss=20)))
        status = await optimizer.optimize(network("eth0", "ethernet"))
        self.assertEqual(status["state"], "rolled-back")
        self.assertIn("Paket kaybı", status["message"])

    async def test_rtt_or_jitter_regression_rolls_back(self):
        for after in (measurement(31, 4), measurement(25, 9)):
            with self.subTest(after=after.remote.to_dict()):
                runner = FakeRunner()
                runner.qdisc["eth0"] = "qdisc pfifo 0: root refcnt 2 limit 1000p"
                optimizer = self.make_optimizer(
                    runner, FakeProbe(measurement(25, 4), after))
                status = await optimizer.optimize(network("eth0", "ethernet"))
                self.assertEqual(status["state"], "rolled-back")
                self.assertIn("kötüleşti", status["message"])

    async def test_connection_loss_rolls_back_immediately_after_measurement(self):
        runner = FakeRunner()
        runner.qdisc["eth0"] = "qdisc pfifo 0: root refcnt 2 limit 1000p"
        optimizer = self.make_optimizer(
            runner, FakeProbe(measurement(), measurement(connected=False)))
        status = await optimizer.optimize(network("eth0", "ethernet"))
        self.assertEqual(status["state"], "rolled-back")
        self.assertIn("Bağlantı testi başarısız", status["message"])

    async def test_disable_is_idempotent(self):
        runner = FakeRunner()
        optimizer = self.make_optimizer(
            runner, FakeProbe(measurement(25, 5), measurement(20, 2)))
        await optimizer.optimize(network())
        self.assertTrue(await optimizer.disable())
        calls_after_first = len(runner.calls)
        self.assertTrue(await optimizer.disable())
        self.assertEqual(len(runner.calls), calls_after_first)

    async def test_cleanup_recovers_persisted_runtime_snapshot(self):
        runner = FakeRunner()
        probe = FakeProbe(measurement(25, 5), measurement(20, 2))
        with tempfile.TemporaryDirectory(prefix="dpibypass-recovery-") as directory:
            path = os.path.join(directory, "latency.json")
            optimizer = LatencyOptimizer(
                runner=runner, which_fn=runner.which, probe=probe,
                state_path=path)
            await optimizer.optimize(network())
            self.assertEqual(runner.power["wlan0"], "off")

            cleanup = LatencyOptimizer(
                runner=runner, which_fn=runner.which, state_path=path)
            self.assertTrue(cleanup.restore_persisted_sync())
            self.assertEqual(runner.power["wlan0"], "on")
            self.assertFalse(os.path.exists(path))

    async def test_user_qdisc_change_is_not_overwritten_on_disable(self):
        runner = FakeRunner()
        runner.qdisc["eth0"] = "qdisc pfifo 0: root refcnt 2 limit 1000p"
        optimizer = self.make_optimizer(
            runner, FakeProbe(measurement(30, 5), measurement(24, 2)))
        await optimizer.optimize(network("eth0", "ethernet"))

        runner.qdisc["eth0"] = "qdisc htb 1: root refcnt 2 r2q 10"
        self.assertTrue(await optimizer.disable())
        self.assertEqual(runner.qdisc["eth0"],
                         "qdisc htb 1: root refcnt 2 r2q 10")


class TestLatencyNetworkChange(OptimizerCase):
    async def test_old_interface_restored_before_new_interface_apply(self):
        from dpibypass.daemon import Daemon

        runner = FakeRunner()
        runner.qdisc["eth0"] = "qdisc pfifo 0: root refcnt 2 limit 1000p"
        runner.qdisc["eth1"] = "qdisc pfifo 0: root refcnt 2 limit 1000p"
        probe = FakeProbe(
            measurement(30, 5), measurement(24, 2),
            measurement(28, 4), measurement(22, 2),
        )
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


class TestLatencyIsolation(OptimizerCase):
    async def test_no_vodafone_firewall_or_ipv6_commands(self):
        runner = FakeRunner()
        runner.qdisc["wlan0"] = "qdisc pfifo 0: root refcnt 2 limit 1000p"
        optimizer = self.make_optimizer(
            runner, FakeProbe(measurement(25, 5), measurement(20, 2)))
        await optimizer.optimize(network())
        forbidden = {"nft", "iptables", "ip6tables", "sysctl", "ip", "nmcli"}
        self.assertFalse(any(call and call[0] in forbidden for call in runner.calls))

    async def test_status_serialization_contains_measurements(self):
        runner = FakeRunner()
        optimizer = self.make_optimizer(
            runner, FakeProbe(measurement(25, 5), measurement(20, 2)))
        data = await optimizer.optimize(network())
        self.assertEqual(set(data), {
            "enabled", "active", "interface", "state", "message",
            "before", "after", "applied", "skipped",
        })
        self.assertEqual(data["before"]["remote"]["median_ms"], 25)
        self.assertEqual(data["after"]["remote"]["median_ms"], 20)
        self.assertTrue(data["active"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
