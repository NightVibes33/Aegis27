#!/usr/bin/env python3

import json
import pathlib
import plistlib
import subprocess
import tempfile
import unittest


REPO = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "cloud_firmware_lab.py"


class CloudFirmwareLabTests(unittest.TestCase):
    def make_fixture(self, root: pathlib.Path) -> None:
        plist_path = root / "System/Library/LaunchDaemons/com.apple.fixture.plist"
        plist_path.parent.mkdir(parents=True)
        plist_path.write_bytes(plistlib.dumps({
            "Label": "com.apple.fixture",
            "Program": "/usr/libexec/fixture-daemon",
            "MachServices": {"com.apple.fixture.service": True},
        }))
        binary = root / "usr/libexec/fixture-daemon"
        binary.parent.mkdir(parents=True)
        binary.write_bytes(
            b"\xcf\xfa\xed\xfe" + b"\x00" * 32
            + b"xpc_dictionary_get_string\x00requestType\x00public.json\x00"
            + b"IOFixtureUserClient\x00performRequest:\x00_TtC7Fixture4Type\x00"
        )
        profile = root / "System/Library/Sandbox/Profiles/fixture.sb"
        profile.parent.mkdir(parents=True)
        profile.write_text("(version 1)\n(deny default)\n")

    def run_script(self, *arguments: str) -> None:
        subprocess.run(["python3", str(SCRIPT), *arguments], check=True)

    def test_plan_and_analyze(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary) / "firmware"
            output = pathlib.Path(temporary) / "report"
            root.mkdir()
            self.make_fixture(root)
            regex = pathlib.Path(temporary) / "program-regex.txt"
            paths = pathlib.Path(temporary) / "program-paths.txt"

            self.run_script(
                "plan", str(root), "--regex-output", str(regex),
                "--paths-output", str(paths),
            )
            self.assertIn("usr/libexec/fixture", regex.read_text())
            self.assertEqual(paths.read_text().strip(), "/usr/libexec/fixture-daemon")

            self.run_script(
                "analyze", str(root), "--device", "iPhone17,3",
                "--build", "24A5380h", "--output-dir", str(output),
            )
            catalog = json.loads((output / "aegis27-probe-catalog.json").read_text())
            report = json.loads((output / "firmware-lab-report.json").read_text())

            self.assertEqual(catalog["sourceBuild"], "24A5380h")
            self.assertEqual(catalog["services"][0]["service"], "com.apple.fixture.service")
            field = catalog["services"][0]["requests"][0]["fields"][0]
            self.assertEqual(field["stringValue"], "com.nightvibes33.Aegis27.bounded-probe")
            self.assertEqual(report["summary"]["matchedMachOBinaries"], 1)
            self.assertEqual(report["summary"]["sandboxProfiles"], 1)
            self.assertIn("performRequest:", report["launchRecords"][0]["binary"]["objcSelectors"])


if __name__ == "__main__":
    unittest.main()
