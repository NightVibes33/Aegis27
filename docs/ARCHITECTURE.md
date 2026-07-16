# Architecture

Aegis27 separates ordinary app behavior from any future privileged primitive.
The shipping baseline has no sandbox escape.

1. `DeviceProfiler` records the exact hardware, OS version, and build without
   using them as a capability claim.
2. `RuntimeCapabilityEvaluator` summarizes only behavior observed by the app.
3. `SnapshotStore` persists baselines and creates stable field-level diffs.
4. `DiagnosticImporter` hashes a selected diagnostic locally and inventories
   markers from a bounded preview.
5. `MobileGestaltReader` reads a small non-unique metadata baseline through a
   dynamically resolved symbol.
6. `FileCapabilityProbe` measures normal sandbox behavior and can create a
   uniquely named, one-shot canary. It never overwrites existing data.
7. `PrivilegedAccessPrimitive` is the only integration boundary for future
   vulnerability research. The current implementation is deliberately inert.
8. `AuditLogger` records every probe and mutation attempt as exportable JSONL.
9. `FileAccessProvider` separates browser behavior from how filesystem access
   is obtained. `StockFileAccessProvider` is functional; the escaped provider
   fails closed until an independently validated primitive is integrated.
10. `ProviderCapabilityValidator` distinguishes metadata, directory listing,
    and bounded file-read results instead of treating policy checks as access.
11. `FileResearchTargetCatalog` keeps personal-data targets disabled by
    default and performs metadata-only inventory when they are enabled.

## Jailbreak prerequisite map

A full modern iOS jailbreak generally requires several independently validated
capabilities. A filesystem sandbox escape alone does not provide them:

- an initial execution and sandbox-escape primitive;
- stable kernel memory access or an equivalent privileged service primitive;
- mitigation bypasses appropriate to the target hardware and build;
- a code-signing/trust strategy;
- a bootstrap and process-injection strategy;
- recovery, rollback, and safe-mode behavior.

Each stage must be version locked, separately testable, and fail closed.

## Installation boundary

An unsigned IPA is a build artifact, not an initial execution method on stock
iOS. A no-computer flow still needs one authorized first-launch path, such as a
normal developer signature, an on-device signing service backed by a valid
certificate, a browser-delivered entry point, or a separately validated
code-signing flaw. Aegis27 does not mislabel packaging as a signing bypass.
