#!/usr/bin/env python3
"""Validate Aegis27 IPSW diff requests and summarize static ipsw diff output.

The summarizer intentionally consumes generic JSON/Markdown output instead of
assuming one ipsw schema. It ranks changed components for manual regression
review; it never labels a static change as a vulnerability and never emits an
exploit payload.
"""
from __future__ import annotations

import argparse
import collections
import datetime as dt
import hashlib
import json
import pathlib
import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Iterable

FORMAT_VERSION = 1
KIND = "ipsw-patch-diff"
SUMMARIZER_VERSION = "1.0"
MAX_REQUEST_BYTES = 64 * 1024
MAX_TEXT_BYTES_PER_FILE = 8 * 1024 * 1024
MAX_EVIDENCE = 4
MAX_EVIDENCE_LENGTH = 320

DEVICE_RE = re.compile(r"^[A-Za-z0-9]+,[0-9]+$")
BUILD_RE = re.compile(r"^[A-Za-z0-9]{3,24}$")
ALLOWED_SURFACES = (
    "firmware",
    "launchd",
    "entitlements",
    "featureFlags",
    "sandbox",
    "functionStarts",
    "cStrings",
    "files",
)
SURFACE_FLAGS = {
    "firmware": "--fw",
    "launchd": "--launchd",
    "entitlements": "--ent",
    "featureFlags": "--feat",
    "sandbox": "--sandbox",
    "functionStarts": "--starts",
    "cStrings": "--strs",
    "files": "--files",
}

PATH_RE = re.compile(
    r"(?P<path>/(?:System|usr|private|Library|Applications|Developer)/[^\s\]\[\)\(\{\}\"'`,;]{2,240})"
)
BUNDLE_RE = re.compile(r"\b(?:com|org|net)\.[A-Za-z0-9_.-]{3,180}\b")
COMPONENT_RE = re.compile(
    r"\b(?:ImageIO|CoreGraphics|CoreMedia|VideoToolbox|AudioToolbox|QuickLook|"
    r"NSKeyedUnarchiver|PropertyListSerialization|libarchive|launchd|sandboxd|"
    r"amfid|trustd|kernelcache|dyld_shared_cache|WebKit|JavaScriptCore|XPC|IOKit)\b",
    re.IGNORECASE,
)

CATEGORY_RULES: list[tuple[str, re.Pattern[str], int]] = [
    ("memory-safety", re.compile(r"(?i)bounds?|overflow|underflow|use.?after.?free|double.?free|dangling|pointer|heap|stack|integer|length|size|memcpy|memmove|allocation"), 30),
    ("code-signing", re.compile(r"(?i)amfid|trustd|code.?sign|signature|trust.?cache|cdhash|entitlement|provision"), 28),
    ("kernel", re.compile(r"(?i)kernelcache|xnu|kext|iokit|userclient|sptm|page.?table|pmap"), 28),
    ("sandbox", re.compile(r"(?i)sandbox|seatbelt|container|mach.?lookup|file.?read|file.?write"), 24),
    ("parser", re.compile(r"(?i)imageio|decode|decoder|parse|parser|unarchive|archive|plist|quicklook|document|font|pdf|jpeg|png|heif|tiff|webp"), 23),
    ("media", re.compile(r"(?i)coremedia|videotoolbox|audiotoolbox|avfoundation|codec|demux|sample.?buffer"), 21),
    ("xpc", re.compile(r"(?i)\bxpc\b|mach.?service|nsxpc|launchd"), 18),
    ("feature", re.compile(r"(?i)feature.?flag|defaults?|experiment|capabilit"), 10),
]


@dataclass
class CandidateAccumulator:
    subject: str
    score: int = 0
    categories: collections.Counter[str] = field(default_factory=collections.Counter)
    evidence: list[str] = field(default_factory=list)
    sources: set[str] = field(default_factory=set)
    fields: set[str] = field(default_factory=set)

    def add(self, text: str, source: str, field_path: str) -> None:
        category, score = classify(text)
        self.score = max(self.score, score)
        self.categories[category] += 1
        self.sources.add(source)
        if field_path:
            self.fields.add(field_path[:180])
        cleaned = compact(text)
        if cleaned and cleaned not in self.evidence and len(self.evidence) < MAX_EVIDENCE:
            self.evidence.append(cleaned[:MAX_EVIDENCE_LENGTH])


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compact(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def load_request(path: pathlib.Path) -> tuple[dict[str, Any], bytes]:
    data = path.read_bytes()
    if not data or len(data) > MAX_REQUEST_BYTES:
        raise ValueError("request must be between 1 byte and 64 KiB")
    value = json.loads(data)
    if not isinstance(value, dict):
        raise ValueError("request root must be an object")
    expected = {
        "formatVersion", "kind", "requestID", "device", "baseBuild", "targetBuild",
        "surfaces", "generatedAt", "sourceBundleIdentifier", "maximumCandidates",
    }
    if set(value) != expected:
        unknown = sorted(set(value) - expected)
        missing = sorted(expected - set(value))
        raise ValueError(f"request fields mismatch; missing={missing}, unknown={unknown}")
    if value["formatVersion"] != FORMAT_VERSION or value["kind"] != KIND:
        raise ValueError("unsupported request format or kind")
    if not isinstance(value["requestID"], str) or len(value["requestID"]) > 64:
        raise ValueError("invalid requestID")
    try:
        uuid.UUID(value["requestID"])
    except (ValueError, AttributeError):
        raise ValueError("invalid requestID") from None
    if not isinstance(value["device"], str) or not DEVICE_RE.fullmatch(value["device"]):
        raise ValueError("invalid device identifier")
    for key in ("baseBuild", "targetBuild"):
        if not isinstance(value[key], str) or not BUILD_RE.fullmatch(value[key]):
            raise ValueError(f"invalid {key}")
    if value["baseBuild"] == value["targetBuild"]:
        raise ValueError("baseBuild and targetBuild must differ")
    surfaces = value["surfaces"]
    if not isinstance(surfaces, list) or not surfaces or len(surfaces) > len(ALLOWED_SURFACES):
        raise ValueError("surfaces must be a non-empty bounded list")
    if any(not isinstance(item, str) or item not in ALLOWED_SURFACES for item in surfaces):
        raise ValueError("request contains an unsupported surface")
    if len(set(surfaces)) != len(surfaces):
        raise ValueError("request contains duplicate surfaces")
    if not isinstance(value["generatedAt"], str) or not 10 <= len(value["generatedAt"]) <= 64:
        raise ValueError("invalid generatedAt")
    if value["sourceBundleIdentifier"] != "com.nightvibes33.Aegis27.v08":
        raise ValueError("unexpected source bundle identifier")
    maximum = value["maximumCandidates"]
    if not isinstance(maximum, int) or not 10 <= maximum <= 200:
        raise ValueError("maximumCandidates must be between 10 and 200")
    return value, data


def classify(text: str) -> tuple[str, int]:
    lowered = text.lower()
    best_category = "component"
    best_score = 5
    for category, pattern, base in CATEGORY_RULES:
        matches = pattern.findall(text)
        if matches:
            score = base + min(24, len(matches) * 3)
            if score > best_score:
                best_category, best_score = category, score
    if any(term in lowered for term in ("added", "removed", "changed", "modified", "diff")):
        best_score += 5
    if PATH_RE.search(text):
        best_score += 4
    return best_category, min(best_score, 100)


def subjects_from(text: str) -> list[str]:
    found: list[str] = []
    for match in PATH_RE.finditer(text):
        found.append(match.group("path").rstrip(".:"))
    found.extend(match.group(0) for match in BUNDLE_RE.finditer(text))
    found.extend(match.group(0) for match in COMPONENT_RE.finditer(text))
    unique: list[str] = []
    for item in found:
        normalized = item.strip()
        if normalized and normalized not in unique:
            unique.append(normalized)
    return unique[:12]


def scalar_text(value: Any) -> str | None:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return value
    return None


def walk_json(value: Any, path: str = "root") -> Iterable[tuple[str, str]]:
    scalar = scalar_text(value)
    if scalar is not None:
        yield path, scalar
        return
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key)[:120]
            child = f"{path}.{key_text}"
            key_scalar = scalar_text(item)
            if key_scalar is not None:
                yield child, f"{key_text}: {key_scalar}"
            else:
                yield from walk_json(item, child)
    elif isinstance(value, list):
        for index, item in enumerate(value[:100_000]):
            yield from walk_json(item, f"{path}[{index}]")


def add_record(accumulators: dict[str, CandidateAccumulator], text: str, source: str, field_path: str) -> None:
    text = compact(text)
    if not text:
        return
    _, score = classify(text)
    subjects = subjects_from(text)
    if not subjects and score < 18:
        return
    if not subjects:
        subject = compact(field_path.split(".")[-1]) or source
        subjects = [subject]
    for subject in subjects:
        key = subject.lower()
        accumulator = accumulators.setdefault(key, CandidateAccumulator(subject=subject))
        accumulator.add(text, source, field_path)


def read_text_limited(path: pathlib.Path) -> str:
    with path.open("rb") as handle:
        data = handle.read(MAX_TEXT_BYTES_PER_FILE + 1)
    if len(data) > MAX_TEXT_BYTES_PER_FILE:
        data = data[:MAX_TEXT_BYTES_PER_FILE]
    return data.decode("utf-8", "replace")


def regression_focus(category: str) -> str:
    return {
        "parser": "Create bounded public-API regression inputs for the changed parser and compare rejection, timing, and crash logs across the two builds.",
        "media": "Exercise documented media APIs with valid and mildly malformed local fixtures; preserve any system-process crash evidence.",
        "xpc": "Review public client-facing schemas and documented APIs only; do not send arbitrary messages to private services.",
        "sandbox": "Compare policy metadata and expected denials; do not attempt to bypass or modify sandbox enforcement.",
        "code-signing": "Review trust and entitlement changes statically; do not alter signatures or trust caches on production devices.",
        "kernel": "Correlate static kernel or IOKit changes with public interfaces and diagnostic logs; no panic or exploitation payload is generated.",
        "memory-safety": "Prioritize manual review of changed length, allocation, and copy logic, then test only through a documented reachable interface.",
        "feature": "Check whether the feature change exposes a documented public behavior difference suitable for a regression test.",
        "component": "Review the component diff manually and identify a documented public entry point before creating any testcase.",
    }.get(category, "Review the static change manually before creating a bounded regression test.")


def summarize(
    raw_dir: pathlib.Path,
    request_path: pathlib.Path,
    output: pathlib.Path,
    summary_path: pathlib.Path | None,
    ipsw_version: str,
) -> dict[str, Any]:
    request, request_bytes = load_request(request_path)
    accumulators: dict[str, CandidateAccumulator] = {}
    raw_artifacts: list[str] = []
    json_count = 0
    markdown_count = 0
    parse_warnings: list[str] = []

    for path in sorted(raw_dir.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(raw_dir).as_posix()
        raw_artifacts.append(relative)
        suffix = path.suffix.lower()
        if suffix == ".json":
            json_count += 1
            try:
                value = json.loads(read_text_limited(path))
                for field_path, text in walk_json(value):
                    add_record(accumulators, text, relative, field_path)
            except (OSError, json.JSONDecodeError, ValueError) as exc:
                parse_warnings.append(f"Could not parse {relative}: {exc}")
        elif suffix in (".md", ".markdown", ".txt", ".log"):
            if suffix in (".md", ".markdown"):
                markdown_count += 1
            try:
                text = read_text_limited(path)
            except OSError as exc:
                parse_warnings.append(f"Could not read {relative}: {exc}")
                continue
            for line_number, line in enumerate(text.splitlines(), 1):
                if line.strip():
                    add_record(accumulators, line, relative, f"line:{line_number}")

    ranked = sorted(
        accumulators.values(),
        key=lambda item: (-item.score, item.subject.lower()),
    )[: request["maximumCandidates"]]
    candidates: list[dict[str, Any]] = []
    category_counts: collections.Counter[str] = collections.Counter()
    for index, item in enumerate(ranked, 1):
        category = item.categories.most_common(1)[0][0] if item.categories else "component"
        category_counts[category] += 1
        candidates.append({
            "id": sha256_bytes(item.subject.lower().encode())[:20],
            "rank": index,
            "score": item.score,
            "category": category,
            "subject": item.subject,
            "sources": sorted(item.sources)[:8],
            "changedFields": sorted(item.fields)[:12],
            "evidence": item.evidence,
            "regressionFocus": regression_focus(category),
            "classification": "static-review-candidate",
        })

    report = {
        "formatVersion": FORMAT_VERSION,
        "kind": KIND,
        "generatedAt": utc_now(),
        "request": request,
        "tool": {
            "summarizerVersion": SUMMARIZER_VERSION,
            "ipswVersion": ipsw_version.strip()[:240],
        },
        "input": {
            "requestSHA256": sha256_bytes(request_bytes),
        },
        "summary": {
            "artifactFiles": len(raw_artifacts),
            "jsonFiles": json_count,
            "markdownFiles": markdown_count,
            "candidateCount": len(candidates),
            "categoryCounts": dict(sorted(category_counts.items())),
        },
        "candidates": candidates,
        "limitations": [
            "Static firmware changes are not proof of a vulnerability or jailbreak primitive.",
            "Ranking is keyword- and path-based and requires manual review.",
            "The workflow does not generate malformed exploit payloads, bypasses, or persistence mechanisms.",
            "A candidate advances only after reproducible device evidence identifies an affected Apple process and exact build.",
        ] + parse_warnings[:20],
        "rawArtifacts": raw_artifacts[:500],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

    if summary_path is not None:
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            "# Aegis27 IPSW Patch-Diff Lab",
            "",
            f"- Device: `{request['device']}`",
            f"- Builds: `{request['baseBuild']}` → `{request['targetBuild']}`",
            f"- Surfaces: {', '.join(request['surfaces'])}",
            f"- Raw artifacts: {len(raw_artifacts)}",
            f"- Ranked static-review candidates: {len(candidates)}",
            "",
            "## Highest-ranked changes",
            "",
        ]
        for item in candidates[:20]:
            lines.append(f"{item['rank']}. **{item['subject']}** — {item['category']} / score {item['score']}")
        lines.extend([
            "",
            "> Static ranking only. No entry is labeled as a vulnerability without reproducible device evidence.",
        ])
        summary_path.write_text("\n".join(lines) + "\n")
    return report


def command_validate(args: argparse.Namespace) -> None:
    request, data = load_request(args.request)
    if args.flags_output:
        flags = [SURFACE_FLAGS[surface] for surface in request["surfaces"]]
        args.flags_output.write_text("\n".join(flags) + "\n")
    if args.env_output:
        lines = [
            f"PATCH_DEVICE={request['device']}",
            f"PATCH_BASE_BUILD={request['baseBuild']}",
            f"PATCH_TARGET_BUILD={request['targetBuild']}",
            f"PATCH_REQUEST_SHA256={sha256_bytes(data)}",
            f"PATCH_MAXIMUM_CANDIDATES={request['maximumCandidates']}",
        ]
        args.env_output.write_text("\n".join(lines) + "\n")
    print(json.dumps({
        "valid": True,
        "device": request["device"],
        "baseBuild": request["baseBuild"],
        "targetBuild": request["targetBuild"],
        "surfaces": request["surfaces"],
        "sha256": sha256_bytes(data),
    }, sort_keys=True))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate")
    validate.add_argument("request", type=pathlib.Path)
    validate.add_argument("--flags-output", type=pathlib.Path)
    validate.add_argument("--env-output", type=pathlib.Path)
    validate.set_defaults(func=command_validate)

    summarize_parser = subparsers.add_parser("summarize")
    summarize_parser.add_argument("raw_dir", type=pathlib.Path)
    summarize_parser.add_argument("--request", required=True, type=pathlib.Path)
    summarize_parser.add_argument("--output", required=True, type=pathlib.Path)
    summarize_parser.add_argument("--summary", type=pathlib.Path)
    summarize_parser.add_argument("--ipsw-version", default="unknown")
    summarize_parser.set_defaults(func=lambda args: summarize(
        args.raw_dir, args.request, args.output, args.summary, args.ipsw_version
    ))
    return parser


def main() -> None:
    args = build_parser().parse_args()
    try:
        args.func(args)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit(str(exc)) from exc


if __name__ == "__main__":
    main()
