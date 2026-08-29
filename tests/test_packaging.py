"""Kurulum ve masaüstü üst verilerinin birbiriyle tutarlılığını doğrular."""

from __future__ import annotations

import configparser
import os
import re
import sys
import unittest
import xml.etree.ElementTree as ET

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from dpibypass import version  # noqa: E402


class TestPackagingMetadata(unittest.TestCase):
    def _desktop_entry(self, filename: str) -> configparser.SectionProxy:
        parser = configparser.ConfigParser(interpolation=None)
        parser.read(os.path.join(ROOT, "data", filename), encoding="utf-8")
        self.assertIn("Desktop Entry", parser)
        return parser["Desktop Entry"]

    def test_desktop_launcher_matches_application_identity(self):
        entry = self._desktop_entry(f"{version.APP_ID}.desktop")
        self.assertEqual(entry["Type"], "Application")
        self.assertEqual(entry["Name"], version.APP_NAME)
        self.assertEqual(entry["Exec"], "dpi-bypass-gui")
        self.assertEqual(entry["Icon"], version.APP_ID)

    def test_autostart_launcher_matches_application_identity(self):
        entry = self._desktop_entry(f"{version.APP_ID}-autostart.desktop")
        self.assertEqual(entry["Type"], "Application")
        self.assertEqual(entry["Name"], version.APP_NAME)
        self.assertEqual(entry["Exec"], "dpi-bypass-gui")
        self.assertEqual(entry["Icon"], version.APP_ID)

    def test_appstream_metadata_matches_version_module(self):
        path = os.path.join(ROOT, "data", f"{version.APP_ID}.metainfo.xml")
        root = ET.parse(path).getroot()

        self.assertEqual(root.findtext("id"), version.APP_ID)
        self.assertEqual(root.findtext("name"), version.APP_NAME)

        releases = root.find("releases")
        self.assertIsNotNone(releases)
        release = releases.find("release")
        self.assertIsNotNone(release)
        self.assertEqual(release.attrib.get("version"), version.__version__)

        launchable = root.find("launchable")
        self.assertIsNotNone(launchable)
        self.assertEqual(launchable.attrib.get("type"), "desktop-id")
        self.assertEqual(launchable.text, f"{version.APP_ID}.desktop")

    def test_installer_constants_match_version_module(self):
        with open(os.path.join(ROOT, "install.sh"), encoding="utf-8") as handle:
            installer = handle.read()

        expected = {
            "APP_NAME": version.APP_NAME,
            "APP_ID": version.APP_ID,
            "APP_VERSION": version.__version__,
        }
        for key, value in expected.items():
            with self.subTest(key=key):
                match = re.search(
                    rf'^\s*{re.escape(key)}="([^"]+)"\s*$',
                    installer,
                    flags=re.MULTILINE,
                )
                self.assertIsNotNone(match, f"install.sh içinde {key} bulunamadı")
                self.assertEqual(match.group(1), value)


if __name__ == "__main__":
    unittest.main(verbosity=2)
