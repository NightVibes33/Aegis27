import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "patch_diff_lab.py"
SPEC = importlib.util.spec_from_file_location("patch_diff_lab", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def request(**overrides):
    value = {
        "formatVersion": 1,
        "kind": "ipsw-patch-diff",
        "requestID": "123e4567-e89b-12d3-a456-426614174000",
        "device": "iPhone17,3",
        "baseBuild": "24A5380h",
        "targetBuild": "24A5390a",
        "surfaces": [
            "firmware",
            "launchd",
            "entitlements",
            "sandbox",
            "functionStarts",
            "cStrings",
        ],
        "generatedAt": "2026-07-28T03:00:00Z",
        "sourceBundleIdentifier": "com.nightvibes33.Aegis27.v08",
        "maximumCandidates": 50,
    }
    value.update(overrides)
    return value


class PatchDiffLabTests(unittest.TestCase):
    def test_validate_and_flags(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            req = root / "request.json"
            req.write_text(json.dumps(request()))
            flags = root / "flags.txt"
            env = root / "env.txt"
            parsed, data = MODULE.load_request(req)
            self.assertEqual(parsed["device"], "iPhone17,3")
            args = type("Args", (), {
                "request": req,
                "flags_output": flags,
                "env_output": env,
            })()
            MODULE.command_validate(args)
            self.assertIn("--sandbox", flags.read_text())
            self.assertIn("PATCH_TARGET_BUILD=24A5390a", env.read_text())
            self.assertEqual(len(MODULE.sha256_bytes(data)), 64)

    def test_rejects_same_build(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "request.json"
            path.write_text(json.dumps(request(targetBuild="24A5380h")))
            with self.assertRaises(ValueError):
                MODULE.load_request(path)

    def test_rejects_unknown_surface(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "request.json"
            path.write_text(json.dumps(request(surfaces=["kernel-panic-payload"])))
            with self.assertRaises(ValueError):
                MODULE.load_request(path)

    def test_summary_ranks_security_relevant_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            raw = root / "raw"
            raw.mkdir()
            (raw / "diff.json").write_text(json.dumps({
                "changed": [
                    {
                        "path": "/System/Library/Frameworks/ImageIO.framework/ImageIO",
                        "detail": "changed bounds length validation in decoder",
                    },
                    {
                        "path": "/System/Library/CoreServices/SpringBoard.app/SpringBoard",
                        "detail": "localized string changed",
                    },
                    {
                        "service": "com.apple.quicklook.ThumbnailsAgent",
                        "detail": "parser allocation size changed",
                    },
                ]
            }))
            (raw / "diff.md").write_text(
                "Removed entitlement from /usr/libexec/trustd code signing path\n"
            )
            req = root / "request.json"
            req.write_text(json.dumps(request()))
            output = root / "analysis.json"
            summary = root / "SUMMARY.md"
            report = MODULE.summarize(raw, req, output, summary, "ipsw test")
            self.assertGreaterEqual(report["summary"]["candidateCount"], 3)
            subjects = [item["subject"] for item in report["candidates"]]
            self.assertTrue(any("ImageIO" in subject for subject in subjects))
            self.assertIn(
                "Static firmware changes are not proof of a vulnerability or jailbreak primitive.",
                report["limitations"],
            )
            self.assertTrue(output.exists())
            self.assertTrue(summary.exists())


if __name__ == "__main__":
    unittest.main()
