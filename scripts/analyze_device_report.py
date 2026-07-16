#!/usr/bin/env python3
"""Create a compact, content-minimizing summary of an Aegis27 device report."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import pathlib
from collections import Counter
from typing import Any


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def summarize_deep_scan(value: dict[str, Any]) -> dict[str, Any]:
    observations = value.get("observations")
    observations = observations if isinstance(observations, list) else []
    outcomes = Counter()
    roots = Counter()
    for item in observations:
        if not isinstance(item, dict):
            continue
        for key in ("metadataOutcome", "listingOutcome", "readOutcome", "writeOutcome"):
            outcome = item.get(key)
            if isinstance(outcome, str) and outcome != "notTested":
                outcomes[f"{key}:{outcome}"] += 1
        path = item.get("path")
        if isinstance(path, str):
            components = [part for part in path.split("/") if part]
            roots["/" + "/".join(components[:2])] += 1
    return {
        "reportType": "deep-scan",
        "observations": len(observations),
        "metadataVisible": value.get("metadataVisibleCount"),
        "readableFiles": value.get("readableFileCount"),
        "listableDirectories": value.get("listableDirectoryCount"),
        "writable": value.get("writableCount"),
        "denied": value.get("deniedCount"),
        "cancelled": value.get("cancelled"),
        "nodeLimitReached": value.get("nodeLimitReached"),
        "operationOutcomes": dict(outcomes.most_common()),
        "topRootCoverage": dict(roots.most_common(20)),
    }


def summarize_attack_surface(value: dict[str, Any]) -> dict[str, Any]:
    report = value.get("report") if isinstance(value.get("report"), dict) else value
    results = report.get("serviceResults") if isinstance(report, dict) else []
    results = results if isinstance(results, list) else []
    dispositions = Counter()
    services = set()
    anomalies = 0
    for item in results:
        if not isinstance(item, dict):
            continue
        if item.get("wasProbed"):
            services.add(str(item.get("service", "unknown")))
            dispositions[str(item.get("disposition", "unknown"))] += 1
            anomalies += bool(item.get("anomalous"))
    validation = report.get("validation", {}) if isinstance(report, dict) else {}
    checks = validation.get("checks", []) if isinstance(validation, dict) else []
    return {
        "reportType": "attack-surface",
        "servicesProbed": len(services),
        "requestsProbed": sum(dispositions.values()),
        "dispositions": dict(dispositions),
        "anomalousResults": anomalies,
        "stableProtocolLeads": report.get("stableProtocolLeadCount") if isinstance(report, dict) else None,
        "protectedAccessConfirmed": validation.get("accessConfirmed") if isinstance(validation, dict) else None,
        "validationChecks": len(checks) if isinstance(checks, list) else 0,
        "crashCorrelations": len(value.get("crashCorrelations", []))
        if isinstance(value.get("crashCorrelations"), list) else 0,
    }


def summarize_jsonl(path: pathlib.Path) -> dict[str, Any]:
    severities = Counter()
    subsystems = Counter()
    malformed = 0
    events = 0
    with path.open("r", errors="replace") as handle:
        for line in handle:
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                malformed += 1
                continue
            if not isinstance(value, dict):
                continue
            events += 1
            severities[str(value.get("severity", "unknown"))] += 1
            subsystems[str(value.get("subsystem", "unknown"))] += 1
    return {
        "reportType": "audit-jsonl",
        "events": events,
        "malformedLines": malformed,
        "severities": dict(severities),
        "subsystems": dict(subsystems.most_common(40)),
    }


def analyze(path: pathlib.Path) -> dict[str, Any]:
    try:
        with path.open("r") as handle:
            value = json.load(handle)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return summarize_jsonl(path)
    if not isinstance(value, dict):
        return {"reportType": "unknown-json", "topLevelType": type(value).__name__}
    if isinstance(value.get("observations"), list):
        return summarize_deep_scan(value)
    if isinstance(value.get("serviceResults"), list) or isinstance(value.get("report"), dict):
        return summarize_attack_surface(value)
    if isinstance(value.get("checks"), list) and "provider" in value:
        statuses = Counter(
            str(item.get("status", "unknown"))
            for item in value["checks"] if isinstance(item, dict)
        )
        return {
            "reportType": "sandbox-validation",
            "checks": len(value["checks"]),
            "statuses": dict(statuses),
            "accessConfirmed": value.get("accessConfirmed"),
            "foreignContainers": value.get("foreignContainerCount"),
        }
    return {
        "reportType": "generic-json",
        "topLevelKeys": sorted(str(key) for key in value)[:100],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--asset-id", required=True)
    parser.add_argument("--kind", required=True)
    parser.add_argument("--hardware", required=True)
    parser.add_argument("--build", required=True)
    args = parser.parse_args()

    actual = sha256(args.input)
    if actual.lower() != args.expected_sha256.lower():
        raise SystemExit("uploaded report SHA-256 does not match dispatch metadata")
    result = {
        "formatVersion": 1,
        "analyzedAt": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "source": {
            "assetID": args.asset_id,
            "bytes": args.input.stat().st_size,
            "sha256": actual,
            "declaredKind": args.kind,
            "hardware": args.hardware,
            "build": args.build,
        },
        "summary": analyze(args.input),
        "privacy": "The compact result excludes raw event details and file contents.",
    }
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
