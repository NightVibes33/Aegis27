# Aegis Crash Triage v0.18

Crash Triage is a bounded on-device workflow for public ImageIO, property-list, and keyed-archive parser research. It does not access other applications, private containers, credentials, or protected system data.

## Workflow

1. Import an image, plist, keyed archive, `.bin`, or `.dat` file no larger than 4 MB.
2. Select ImageIO, PropertyListSerialization, or NSKeyedUnarchiver.
3. Run a deterministic campaign. Every candidate is saved and journaled before parsing with its seed, mutation operations, SHA-256, size, parser, device build, and timestamp.
4. If Aegis stops before the journal completes, relaunch it and import the matching `.ips` or panic log. A pending journal alone is not treated as proof of a crash.
5. Crash logs are normalized and deduplicated by process, exception, termination reason, and top-frame signature.
6. Confirmed crash candidates can enter restart-aware deletion minimization. Candidates that survive continue automatically. A candidate that terminates Aegis remains pending across relaunch so the smaller input can be retained or rejected explicitly.

## Classification rules

- Parser rejection: normal parser behavior, not a vulnerability.
- App crash: Aegis27 terminated without a stronger memory-corruption classification.
- System-service crash: an imported crash log identifies another process.
- Memory-corruption signal: the imported log contains evidence such as `EXC_BAD_ACCESS`, `SIGSEGV`, `SIGBUS`, invalid-address faults, PAC failure, or explicit memory-corruption wording.
- Resource termination: jetsam, watchdog, CPU, memory-pressure, or resource-limit termination.
- Assertion failure: abort, assertion, precondition, or fatal-error termination.

These labels are triage aids, not proof of exploitability. Any security-impact claim still requires reliable reproduction, root-cause analysis, and responsible disclosure.
