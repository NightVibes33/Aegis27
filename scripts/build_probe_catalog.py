#!/usr/bin/env python3
"""Build a bounded Aegis27 probe catalog from an extracted matching firmware.

The generator only records candidate dictionary keys and emits inert values.
It does not derive or emit destructive operation values, entitlement bypasses,
paths to personal data, or serialized exploit payloads.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import re


SERVICE_NAMES = {
    "mobileassetd": "com.apple.mobileassetd",
    "mobilegestalt": "com.apple.mobilegestalt.xpc",
    "cfprefsd": "com.apple.cfprefsd.daemon",
    "fileprovider": "com.apple.FileProvider",
    "containermanagerd": "com.apple.containermanagerd",
}
KEY_HINT = re.compile(
    rb"(?i)(command|operation|request|action|options|asset|identifier|type|path|reply)"
)
TOKEN = re.compile(rb"^[A-Za-z][A-Za-z0-9_.-]{2,95}$")
ASCII_RUN = re.compile(rb"[ -~]{3,128}")


def candidate_keys(path: pathlib.Path) -> list[str]:
    try:
        data = path.read_bytes()
    except OSError:
        return []
    keys: set[str] = set()
    for match in ASCII_RUN.finditer(data):
        raw = match.group(0)
        if KEY_HINT.search(raw) and TOKEN.fullmatch(raw):
            keys.add(raw.decode("ascii"))
        if len(keys) >= 32:
            break
    return sorted(keys)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("firmware_root", type=pathlib.Path)
    parser.add_argument("--build", required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()

    discovered: dict[str, dict[str, object]] = {}
    for path in sorted(p for p in args.firmware_root.rglob("*") if p.is_file()):
        lower = path.name.lower()
        matched = next((key for key in SERVICE_NAMES if key in lower), None)
        if matched is None:
            continue
        service_name = SERVICE_NAMES[matched]
        entry = discovered.setdefault(service_name, {
            "subsystem": matched,
            "paths": [],
            "keys": set(),
        })
        entry["paths"].append(str(path))
        entry["keys"].update(candidate_keys(path))

    services = []
    parser_surfaces = []
    for service_name, entry in sorted(discovered.items()):
        keys = sorted(entry["keys"])
        requests = []
        for index, key in enumerate(keys[:8]):
            requests.append({
                "id": f"strings-{index}-{key.lower()}",
                "label": f"Inert value for firmware string key {key}",
                "source": entry["paths"][0],
                "fields": [{
                    "key": key,
                    "type": "string",
                    "stringValue": "com.nightvibes33.Aegis27.bounded-probe",
                    "unsignedIntegerValue": None,
                    "booleanValue": None,
                }],
            })
        services.append({
            "service": service_name,
            "subsystem": entry["subsystem"],
            "binaryPath": entry["paths"][0],
            "requests": requests,
        })
        if entry["subsystem"] in {"mobileassetd", "fileprovider"}:
            parser_surfaces.append({
                "id": f"{entry['subsystem']}-metadata",
                "label": f"{entry['subsystem']} controlled metadata boundary",
                "uniformType": "public.data",
                "boundary": service_name,
                "source": entry["paths"][0],
            })

    catalog = {
        "formatVersion": 1,
        "sourceBuild": args.build,
        "generatedAt": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "services": services[:64],
        "parserSurfaces": parser_surfaces[:32],
        "ioKitClasses": [],
    }
    args.output.write_text(json.dumps(catalog, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
