"""NetworkManager bağlantı denetimi korumaları için regresyon testleri.

Bu testler ağ erişimi veya gerçek NetworkManager servisi gerektirmez. Amaç,
masaüstü bağlantı denetimi uçlarının otomatik keşif tarafından yanlışlıkla
hedeflenmesini önleyen mantığın davranışını sabitlemektir.
"""

from __future__ import annotations

import os
import subprocess
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "src"))

from dpibypass import connectivity  # noqa: E402


class TestConnectivityHostname(unittest.TestCase):
    def test_http_and_https_hosts_are_normalized(self):
        self.assertEqual(
            connectivity._hostname(" HTTPS://Portal.Example.COM./check "),
            "portal.example.com",
        )
        self.assertEqual(
            connectivity._hostname("http://example.net/path?q=1"),
            "example.net",
        )

    def test_non_http_and_malformed_uris_are_ignored(self):
        for uri in (
            "file:///tmp/check",
            "ftp://example.com/check",
            "not-a-uri",
            "https://[broken",
            "",
        ):
            with self.subTest(uri=uri):
                self.assertEqual(connectivity._hostname(uri), "")


class TestNetworkManagerCheckDomains(unittest.TestCase):
    def test_known_domains_are_returned_without_networkmanager(self):
        with mock.patch.object(connectivity, "which", return_value=None):
            result = connectivity.networkmanager_check_domains()

        self.assertEqual(result, connectivity.KNOWN_CHECK_DOMAINS)
        self.assertIsNot(result, connectivity.KNOWN_CHECK_DOMAINS)

    def test_print_config_adds_valid_connectivity_uris(self):
        output = """
[connectivity]
uri=https://Portal.Example.COM./check_network_status.txt
interval=300

[other]
uri = http://second.example.net/probe
uri = ftp://ignored.example.org/probe
"""
        completed = subprocess.CompletedProcess(
            ["/usr/sbin/NetworkManager", "--print-config"],
            0,
            stdout=output,
            stderr="",
        )

        with mock.patch.object(
            connectivity, "which", return_value="/usr/sbin/NetworkManager"
        ), mock.patch.object(connectivity, "run", return_value=completed) as run:
            result = connectivity.networkmanager_check_domains()

        self.assertIn("portal.example.com", result)
        self.assertIn("second.example.net", result)
        self.assertNotIn("ignored.example.org", result)
        self.assertTrue(connectivity.KNOWN_CHECK_DOMAINS.issubset(result))
        run.assert_called_once_with(
            ["/usr/sbin/NetworkManager", "--print-config"], timeout=10
        )

    def test_failed_print_config_falls_back_to_known_domains(self):
        completed = subprocess.CompletedProcess(
            ["/usr/bin/NetworkManager", "--print-config"],
            1,
            stdout="uri=https://should-not-be-used.example/check\n",
            stderr="permission denied",
        )

        with mock.patch.object(
            connectivity, "which", return_value="/usr/bin/NetworkManager"
        ), mock.patch.object(connectivity, "run", return_value=completed):
            result = connectivity.networkmanager_check_domains()

        self.assertEqual(result, connectivity.KNOWN_CHECK_DOMAINS)
        self.assertNotIn("should-not-be-used.example", result)

    def test_each_call_returns_an_independent_set(self):
        with mock.patch.object(connectivity, "which", return_value=None):
            first = connectivity.networkmanager_check_domains()
            first.add("temporary.example")
            second = connectivity.networkmanager_check_domains()

        self.assertNotIn("temporary.example", second)
        self.assertEqual(second, connectivity.KNOWN_CHECK_DOMAINS)


if __name__ == "__main__":
    unittest.main(verbosity=2)
