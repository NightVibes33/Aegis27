#!/usr/bin/env python3

import hashlib
import json
import pathlib
import subprocess
import tempfile
import unittest


REPO = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "analyze_device_report.py"


class DeviceReportAnalyzerTests(unittest.TestCase):
    def test_deep_scan_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = pathlib.Path(temporary) / "scan.json"
            output = pathlib.Path(temporary) / "analysis.json"
            source.write_text(json.dumps({
                "observations": [{
                    "path": "/System/Library/example",
                    "metadataOutcome": "success",
                    "listingOutcome": "notTested",
                    "readOutcome": "success",
                    "writeOutcome": "permissionDenied",
                }],
                "metadataVisibleCount": 1,
                "readableFileCount": 1,
                "listableDirectoryCount": 0,
                "writableCount": 0,
                "deniedCount": 1,
                "cancelled": False,
                "nodeLimitReached": False,
            }))
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            subprocess.run([
                "python3", str(SCRIPT), str(source), "--output", str(output),
                "--expected-sha256", digest, "--asset-id", "123",
                "--kind", "deep-scan", "--hardware", "iPhone17,3",
                "--build", "24A5380h",
            ], check=True)
            result = json.loads(output.read_text())
            self.assertEqual(result["summary"]["reportType"], "deep-scan")
            self.assertEqual(result["summary"]["observations"], 1)
            self.assertEqual(result["source"]["sha256"], digest)


if __name__ == "__main__":
    unittest.main()
