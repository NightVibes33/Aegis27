# Aegis27 IPSW Patch-Diff Lab

The v0.19 Patch-Diff Lab compares two exact Apple IPSWs for one hardware identifier on a GitHub macOS runner. The app submits only a compact JSON request through the existing unpublished runner inbox.

The workflow resolves and verifies both Apple firmware URLs, downloads both complete IPSWs, and runs selected `ipsw diff` surfaces:

- packaged firmware
- launchd configurations
- entitlements
- feature flags
- compiled sandbox profiles
- Mach-O function starts
- C strings
- optional broad filesystem inventory

The raw diff remains a static artifact. `scripts/patch_diff_lab.py` produces a compact report that ranks changed paths and components for manual regression review. Every result is labeled `static-review-candidate`; static differences are never reported as vulnerabilities, jailbreak primitives, or exploit chains.

A candidate advances only when a bounded device test on the exact build produces reproducible evidence tied to an Apple process, preserved input, and a matching diagnostic log.

## Storage and privacy

- Full IPSWs are deleted from the runner before artifact upload.
- The app receives only the compact JSON report.
- The GitHub token remains a this-device-only Keychain item.
- No App Group, shared Keychain group, private entitlement, kernel panic payload, signature modification, or persistence mechanism is added.
