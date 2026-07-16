#!/usr/bin/env python3
"""Build evidence and an inert Aegis27 probe catalog from extracted iOS files.

The tool has two phases so a CI runner does not need to unpack an entire IPSW:

* ``plan`` reads extracted launchd plists and emits one regex matching the
  executable paths they reference.
* ``analyze`` inventories those plists and executables, records bounded static
  evidence, and emits a format-v1 catalog accepted by Aegis27.

No firmware bytes, entitlement values, or discovered string values are copied
to the probe catalog. Typed requests always use a fixed inert marker.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import pathlib
import plistlib
import re
import subprocess
from dataclasses import dataclass, field
from typing import Any, Iterable


MARKER = "com.nightvibes33.Aegis27.bounded-probe"
MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
    b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca",
}
ASCII_RUN = re.compile(rb"[ -~]{3,160}")
UTF16_RUN = re.compile(rb"(?:[ -~]\x00){3,120}")
TOKEN = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{2,95}$")
SERVICE = re.compile(r"^(?:[A-Za-z0-9-]+\.){2,}[A-Za-z0-9_-]+$")
KEY_HINT = re.compile(
    r"(?i)(command|operation|request|action|option|asset|identifier|type|path|"
    r"reply|message|client|version|name|url|data|format|mode|flags|token)"
)
IOKIT = re.compile(
    r"^(?:IO[A-Z][A-Za-z0-9_]{3,}|Apple[A-Z][A-Za-z0-9_]{3,}(?:UserClient|Driver))$"
)
UTI = re.compile(r"^(?:public|com\.apple)\.[A-Za-z0-9.-]{2,100}$")
OBJC_SELECTOR = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?::[A-Za-z_][A-Za-z0-9_]*)*:$")
SWIFT_SYMBOL = re.compile(r"^(?:_?\$s|_TtC)[A-Za-z0-9_$]{4,156}$")
XPC_IMPORTS = (
    "xpc_dictionary_get_", "xpc_dictionary_set_", "xpc_connection_create",
    "NSXPCConnection", "NSXPCInterface",
)
SENSITIVE_ENTITLEMENT_HINTS = (
    "mach-lookup", "sandbox", "container", "file", "security", "private",
    "rootless", "platform-application",
)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def relative_display(path: pathlib.Path, root: pathlib.Path) -> str:
    try:
        return "/" + path.relative_to(root).as_posix().lstrip("/")
    except ValueError:
        return path.as_posix()


def load_plist(path: pathlib.Path) -> dict[str, Any] | None:
    try:
        value = plistlib.loads(path.read_bytes())
    except (OSError, plistlib.InvalidFileException, ValueError):
        return None
    return value if isinstance(value, dict) else None


def iter_launch_records(root: pathlib.Path) -> Iterable[tuple[pathlib.Path, dict[str, Any]]]:
    for path in sorted(root.rglob("*.plist")):
        value = load_plist(path)
        if not value:
            continue
        if any(key in value for key in ("MachServices", "Program", "ProgramArguments")):
            yield path, value


def launch_program(value: dict[str, Any]) -> str | None:
    program = value.get("Program")
    if isinstance(program, str) and program.startswith("/"):
        return program
    arguments = value.get("ProgramArguments")
    if isinstance(arguments, list) and arguments and isinstance(arguments[0], str):
        return arguments[0] if arguments[0].startswith("/") else None
    return None


def mach_services(value: dict[str, Any]) -> list[str]:
    raw = value.get("MachServices")
    if not isinstance(raw, dict):
        return []
    return sorted(key for key in raw if isinstance(key, str) and SERVICE.fullmatch(key))


def build_extraction_regex(root: pathlib.Path, maximum: int) -> tuple[str, list[str]]:
    programs = sorted({
        program
        for _, value in iter_launch_records(root)
        if (program := launch_program(value)) is not None
    })[:maximum]
    if not programs:
        raise SystemExit("No absolute launchd Program paths found in extracted plists")
    # Python escapes a few characters (notably '-') that RE2 rejects as
    # identity escapes. Escape only actual RE2 metacharacters here.
    def re2_escape(value: str) -> str:
        return re.sub(r"([\\.+*?()|\[\]{}^$])", r"\\\1", value)

    alternatives = "|".join(re2_escape(path.lstrip("/")) for path in programs)
    # ipsw uses Go's RE2 syntax, which intentionally has no non-capturing groups.
    return rf"^/?({alternatives})$", programs


def strings_from(data: bytes) -> list[str]:
    values = {match.group(0).decode("ascii", "ignore") for match in ASCII_RUN.finditer(data)}
    for match in UTF16_RUN.finditer(data):
        values.add(match.group(0).decode("utf-16-le", "ignore"))
    return sorted(values)


def is_macho(data: bytes) -> bool:
    return data[:4] in MACHO_MAGICS


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def codesign_entitlement_keys(path: pathlib.Path) -> list[str]:
    try:
        result = subprocess.run(
            ["codesign", "-d", "--entitlements", ":-", str(path)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, check=False,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return []
    payload = result.stdout
    start = payload.find(b"<?xml")
    if start < 0:
        start = result.stderr.find(b"<?xml")
        payload = result.stderr
    if start < 0:
        return []
    try:
        value = plistlib.loads(payload[start:])
    except (plistlib.InvalidFileException, ValueError):
        return []
    return sorted(str(key) for key in value) if isinstance(value, dict) else []


@dataclass
class BinaryEvidence:
    path: str
    size: int
    digest: str
    xpc_imports: list[str]
    candidate_keys: list[str]
    io_kit_classes: list[str]
    parser_types: list[str]
    objc_selectors: list[str]
    swift_symbols: list[str]
    entitlement_keys: list[str]

    @property
    def score(self) -> int:
        return (
            20 + min(30, len(self.xpc_imports) * 6)
            + min(24, len(self.candidate_keys) * 3)
            + min(12, len(self.entitlement_keys))
        )


@dataclass
class LaunchEvidence:
    plist_path: str
    label: str
    program: str | None
    services: list[str]
    binary: BinaryEvidence | None = None
    notes: list[str] = field(default_factory=list)


def analyze_binary(path: pathlib.Path, root: pathlib.Path, byte_limit: int) -> BinaryEvidence | None:
    try:
        size = path.stat().st_size
        if size <= 0 or size > byte_limit:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if not is_macho(data):
        return None
    values = strings_from(data)
    imports = sorted({hint for hint in XPC_IMPORTS if any(hint in item for item in values)})
    keys = sorted({item for item in values if TOKEN.fullmatch(item) and KEY_HINT.search(item)})[:32]
    io_classes = sorted({item for item in values if IOKIT.fullmatch(item)})[:64]
    parser_types = sorted({item for item in values if UTI.fullmatch(item)})[:64]
    objc_selectors = sorted({item for item in values if OBJC_SELECTOR.fullmatch(item)})[:64]
    swift_symbols = sorted({item for item in values if SWIFT_SYMBOL.fullmatch(item)})[:64]
    return BinaryEvidence(
        path=relative_display(path, root),
        size=size,
        digest=sha256(data),
        xpc_imports=imports,
        candidate_keys=keys,
        io_kit_classes=io_classes,
        parser_types=parser_types,
        objc_selectors=objc_selectors,
        swift_symbols=swift_symbols,
        entitlement_keys=codesign_entitlement_keys(path),
    )


def path_index(root: pathlib.Path) -> dict[str, list[pathlib.Path]]:
    index: dict[str, list[pathlib.Path]] = {}
    for path in root.rglob("*"):
        if path.is_file():
            index.setdefault(path.name, []).append(path)
    return index


def match_program(program: str | None, index: dict[str, list[pathlib.Path]]) -> pathlib.Path | None:
    if not program:
        return None
    candidates = index.get(pathlib.PurePosixPath(program).name, [])
    suffix = program.lstrip("/")
    exact = [path for path in candidates if path.as_posix().endswith(suffix)]
    return (exact or candidates or [None])[0]


def safe_request_id(index: int, key: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9_.-]", "-", key.lower())[:56]
    return f"static-{index}-{normalized}"


def request_for(key: str, source: str, index: int) -> dict[str, Any]:
    return {
        "id": safe_request_id(index, key),
        "label": f"Inert marker for statically observed key {key}"[:120],
        "source": source[:240],
        "fields": [{
            "key": key,
            "type": "string",
            "stringValue": MARKER,
            "unsignedIntegerValue": None,
            "booleanValue": None,
        }],
    }


def analyze(args: argparse.Namespace) -> None:
    root: pathlib.Path = args.firmware_root.resolve()
    output: pathlib.Path = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    index = path_index(root)
    records: list[LaunchEvidence] = []
    scanned_bytes = 0

    sandbox_profiles: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        display = relative_display(path, root)
        if not path.is_file() or "sandbox" not in display.lower() or "profile" not in display.lower():
            continue
        if len(sandbox_profiles) >= 256:
            break
        try:
            data = path.read_bytes()
        except OSError:
            continue
        sandbox_profiles.append({"path": display, "size": len(data), "sha256": sha256(data)})

    for plist_path, value in iter_launch_records(root):
        services = mach_services(value)
        program = launch_program(value)
        if not services:
            continue
        binary_path = match_program(program, index)
        binary = None
        notes: list[str] = []
        if binary_path is None:
            notes.append("program binary was not present in the bounded extraction")
        else:
            try:
                binary_size = binary_path.stat().st_size
            except OSError:
                binary_size = 0
            if scanned_bytes + binary_size > args.max_total_bytes:
                notes.append("binary skipped because the aggregate scan budget was exhausted")
            else:
                binary = analyze_binary(binary_path, root, args.max_file_bytes)
                scanned_bytes += binary_size
                if binary is None:
                    notes.append("program was not a readable Mach-O within the per-file limit")
        label = value.get("Label") if isinstance(value.get("Label"), str) else plist_path.stem
        records.append(LaunchEvidence(
            plist_path=relative_display(plist_path, root), label=label,
            program=program, services=services, binary=binary, notes=notes,
        ))

    ranked: list[tuple[int, str, LaunchEvidence]] = []
    for record in records:
        for service in record.services:
            score = 50 + (record.binary.score if record.binary else 0)
            ranked.append((score, service, record))
    ranked.sort(key=lambda item: (-item[0], item[1]))

    services: list[dict[str, Any]] = []
    seen: set[str] = set()
    all_io: set[str] = set()
    parser_surfaces: list[dict[str, str]] = []
    for score, service, record in ranked:
        if service in seen or len(services) >= 64:
            continue
        seen.add(service)
        binary = record.binary
        keys = binary.candidate_keys[:8] if binary else []
        source = binary.path if binary else record.plist_path
        services.append({
            "service": service,
            "subsystem": record.label[:80],
            "binaryPath": binary.path if binary else record.program,
            "requests": [request_for(key, source, index) for index, key in enumerate(keys)],
        })
        if binary:
            all_io.update(binary.io_kit_classes)
            for parser_type in binary.parser_types:
                if len(parser_surfaces) >= 32:
                    break
                parser_surfaces.append({
                    "id": f"static-{len(parser_surfaces)}",
                    "label": f"Statically referenced type {parser_type}"[:120],
                    "uniformType": parser_type,
                    "boundary": service,
                    "source": binary.path[:240],
                })

    catalog = {
        "formatVersion": 1,
        "sourceBuild": args.build,
        "generatedAt": utc_now(),
        "services": services,
        "parserSurfaces": parser_surfaces,
        "ioKitClasses": sorted(all_io)[:64],
    }
    report = {
        "formatVersion": 1,
        "generatedAt": utc_now(),
        "target": {"device": args.device, "build": args.build},
        "limits": {
            "maximumFileBytes": args.max_file_bytes,
            "maximumTotalBytes": args.max_total_bytes,
            "catalogServices": 64,
            "requestsPerService": 8,
        },
        "summary": {
            "launchRecords": len(records),
            "machServices": len({service for record in records for service in record.services}),
            "matchedMachOBinaries": sum(record.binary is not None for record in records),
            "scannedBytes": scanned_bytes,
            "catalogServices": len(services),
            "typedRequests": sum(len(service["requests"]) for service in services),
            "ioKitClasses": len(catalog["ioKitClasses"]),
            "parserSurfaces": len(parser_surfaces),
            "sandboxProfiles": len(sandbox_profiles),
        },
        "method": {
            "serviceEvidence": "launchd MachServices mapped to its Program executable",
            "schemaEvidence": "bounded printable-token recovery from matched Mach-O files",
            "warning": (
                "Static strings are candidates, not proven protocol semantics. The iPhone app "
                "uses only fixed inert values and requires runtime reproduction plus an impact oracle."
            ),
        },
        "launchRecords": [
            {
                "plistPath": record.plist_path,
                "label": record.label,
                "program": record.program,
                "services": record.services,
                "notes": record.notes,
                "binary": None if record.binary is None else {
                    "path": record.binary.path,
                    "size": record.binary.size,
                    "sha256": record.binary.digest,
                    "xpcImports": record.binary.xpc_imports,
                    "candidateKeys": record.binary.candidate_keys,
                    "ioKitClasses": record.binary.io_kit_classes,
                    "parserTypes": record.binary.parser_types,
                    "objcSelectors": record.binary.objc_selectors,
                    "swiftSymbols": record.binary.swift_symbols,
                    "entitlementKeys": record.binary.entitlement_keys,
                    "sensitiveEntitlementKeyCount": sum(
                        any(hint in key.lower() for hint in SENSITIVE_ENTITLEMENT_HINTS)
                        for key in record.binary.entitlement_keys
                    ),
                    "confidenceScore": record.binary.score,
                },
            }
            for record in records
        ],
        "sandboxProfiles": sandbox_profiles,
    }

    catalog_path = output / "aegis27-probe-catalog.json"
    report_path = output / "firmware-lab-report.json"
    catalog_path.write_text(json.dumps(catalog, indent=2, sort_keys=True) + "\n")
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    (output / "SUMMARY.md").write_text(
        "# Aegis27 cloud firmware lab\n\n"
        f"- Device: `{args.device}`\n- Build: `{args.build}`\n"
        f"- Launch records: {report['summary']['launchRecords']}\n"
        f"- Mach services: {report['summary']['machServices']}\n"
        f"- Matched Mach-O programs: {report['summary']['matchedMachOBinaries']}\n"
        f"- Catalog services: {report['summary']['catalogServices']}\n"
        f"- Inert typed requests: {report['summary']['typedRequests']}\n\n"
        "Static candidates are not vulnerability findings. Import the catalog into Aegis27, "
        "run the bounded suite, and require repeatability plus the protected-access oracle.\n"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    plan = subparsers.add_parser("plan", help="emit a regex for launchd Program paths")
    plan.add_argument("firmware_root", type=pathlib.Path)
    plan.add_argument("--regex-output", type=pathlib.Path, required=True)
    plan.add_argument("--paths-output", type=pathlib.Path, required=True)
    plan.add_argument("--maximum-programs", type=int, default=768)

    scan = subparsers.add_parser("analyze", help="build evidence and a probe catalog")
    scan.add_argument("firmware_root", type=pathlib.Path)
    scan.add_argument("--build", required=True)
    scan.add_argument("--device", required=True)
    scan.add_argument("--output-dir", type=pathlib.Path, required=True)
    scan.add_argument("--max-file-bytes", type=int, default=128 * 1024 * 1024)
    scan.add_argument("--max-total-bytes", type=int, default=2 * 1024 * 1024 * 1024)

    args = parser.parse_args()
    if args.command == "plan":
        regex, programs = build_extraction_regex(args.firmware_root.resolve(), args.maximum_programs)
        args.regex_output.write_text(regex + "\n")
        args.paths_output.write_text("\n".join(programs) + "\n")
    else:
        analyze(args)


if __name__ == "__main__":
    main()
