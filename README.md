# Aegis27

Aegis27 is an iOS research harness for measuring a device's observed runtime
capabilities. It establishes reproducible baselines for curated MobileGestalt
reads, strict-folder capability probes, one-shot write canaries, snapshot
comparison, diagnostic correlation, and structured evidence collection.

## Current status

**This is not currently a jailbreak.** The initial version intentionally does
not contain a sandbox escape, kernel exploit, PPL bypass, code-signing bypass,
or persistence mechanism. It provides a safe and testable place to integrate a
privileged primitive only after that primitive has been independently validated
on the exact target build.

## v0.5 research workflow

1. Tap **Refresh** to collect the full baseline.
2. Save an initial snapshot.
3. Run one repeatable, non-destructive experiment.
4. Optionally import a user-selected crash report or diagnostic file. The app
   hashes the file locally and counts relevant markers in only the first 4 MB.
5. Save again to see exactly which measured fields changed.

The runtime capability matrix replaces model/build allowlisting. This lets the
same IPA collect evidence on normal retail devices, betas, and authorized
research devices without claiming that any environment is privileged.

## v0.6 file-provider workflow

The app also includes a dedicated **Verify** mode for decisive protected-access
checks. It attempts a bounded read of
`/var/mobile/Library/Preferences/com.apple.springboard.plist` and lists
`/var/mobile/Containers/Data/Application` to detect containers other than
Aegis27's own. Metadata-only visibility does not count as a pass.

The **Scan** mode performs a root-balanced capability inventory from standard
system, mobile-user, and container roots. Its default all-reachable mode has no
path or depth ceiling and advances each root in turn so a large public subtree
cannot starve the other targets. It records metadata, directory-listing,
one-byte read, and optional create-and-remove write results; does not retain
file contents or follow symbolic links; and also repeats the evidence-backed
Mach-service reachability inventory. Limited path/depth mode remains available
for faster diagnostic runs.

The **Files** tab adds the parts of the filesystem research architecture that
can operate without an escape:

- a common `FileAccessProvider` boundary;
- a working stock-sandbox provider;
- a fail-closed escaped-provider placeholder;
- provider capability validation based on real operations;
- read-only directory navigation and current-directory filtering;
- bounded 64 KiB text previews and 512-byte hex previews;
- symbolic-link refusal;
- a MobileGestalt/system target catalog; and
- metadata-only personal-data targets that require explicit opt-in.

The browser does not claim that an allowed sandbox-policy rule is successful
filesystem access. Each metadata, listing, and read operation is measured
through the selected provider.

Version 0.6.1 records provider selection, capability validation, target
inventory, directory listing, and bounded-preview outcomes in the same JSONL
audit log used by the Research tab. Preview contents are never written to the
log.

Version 0.7 presents those capabilities as a native file manager: compact
provider status, editable address bar, tappable breadcrumbs, list/grid layouts,
name/date/size sorting, hidden-file control, extension-aware icons, pull to
refresh, copy-path context menus, and a dedicated preview sheet. Provider
validation and research targets live in a separate inspector instead of
interrupting normal browsing.

Version 0.8 adds an evidence-labeled beta-3 service matrix derived from the
public `24A5370h` to `24A5380h` firmware diff. It expands read-only policy and
bootstrap lookup coverage around MobileAsset, Books, MobileBackup, CacheDelete,
FileProvider, container management, and AFC. It also separates app-container
success, protected metadata visibility, and protected-data access so a metadata
`stat` can no longer inflate the protected-access result. Missing paths,
permission denial, unavailable providers, and skipped checks are classified
independently.

Version 0.9 adds a dedicated **Attack Surface** mode. It sends exactly one
empty XPC dictionary to each catalog service that already resolves from the
stock app sandbox, applies a 750 ms response deadline, classifies only the
reply type, and checks whether service reachability changed. It then always
runs the decisive protected-file and foreign-container validation. Empty
dictionary rejection is expected and is not reported as a vulnerability;
service-specific commands, attacker-selected paths, and destructive requests
are outside this mode. A compact JSON report avoids another filesystem-sized
export.

Version 0.10 expands that mode into a bounded differential suite:

- exact-build firmware catalog import with strict size, service, request, and
  field limits;
- three repetitions of empty and inert typed XPC dictionary schemas;
- response fingerprints made only from reply type and dictionary key names—
  reply values are never retained;
- tiny valid and truncated JSON, plist, and PNG corpora measured both locally
  and through the public QuickLook thumbnail boundary, with a two-second
  deadline per QuickLook request;
- an IOKit match/open-type-0/close inventory that never invokes external
  methods;
- `.ips`/diagnostic correlation by timestamp, process, probe identifier, and
  security-relevant termination markers;
- persisted cross-run and cross-boot response comparisons; and
- protected-file and foreign-container checks after every XPC repetition and
  after the complete suite.

Generate an inert catalog from an extracted copy of the matching firmware:

```sh
python3 scripts/build_probe_catalog.py /path/to/extracted/firmware \
  --build 24A5380h \
  --output aegis27-probe-catalog.json
```

The generator uses firmware strings only to identify candidate dictionary
keys. It emits a fixed inert marker value and never generates destructive
operation values, personal-data paths, or exploit payloads.

Version 0.11 adds an in-app **PoC candidate workflow** after discovery. It
ranks protected-access, correlated service-crash, typed-XPC, IOKit, parser,
and baseline-XPC evidence; reproduces the strongest typed request; greedily
removes schema fields while preserving the three-run response fingerprint;
runs the protected-access validator after every candidate variant; classifies
the likely primitive family; applies a lead-specific cross-boot gate; and
exports a self-contained `poc-candidate-latest.json` manifest. A stable reply,
daemon crash, parser timeout, or open IOKit user client remains a candidate.
Only an actual protected read or foreign-container listing is labeled
controlled security impact.

## Safety behavior

- The target model, OS version, and build are recorded, not hard-coded.
- A write canary still requires explicit one-shot arming and confirmation.
- The exported log includes MobileGestalt values and syscall-level sandbox
  policy decisions for candidate paths and Mach services.
- Bootstrap lookups distinguish services that merely have an allowed policy
  rule from services that actually resolve on the target build.
- Strict-folder writes use a random `O_EXCL`-style canary and immediately remove
  only that exact file.
- Existing files are never overwritten, truncated, renamed, or deleted.
- Every probe is recorded in an exportable JSONL research log.
- No private entitlements are claimed.

## GitHub build

The included workflow uses a GitHub `macos-26` runner, generates the Xcode
project with XcodeGen, builds for physical iOS devices with signing disabled,
and uploads:

- `Aegis27-unsigned.ipa`
- `Aegis27-unsigned.ipa.sha256`

Run **Actions → Build unsigned research IPA → Run workflow**. The result is an
unsigned research artifact; stock iOS will not install an unsigned IPA without
an applicable signing or code-signing bypass.

## Local Xcode build

```sh
brew install xcodegen
xcodegen generate
xcodebuild -project Aegis27.xcodeproj -scheme Aegis27 -sdk iphoneos build
```

## Privileged primitive boundary

The `PrivilegedAccessPrimitive` protocol is the integration boundary for a
future, independently validated capability. Aegis27 does not manufacture or
simulate that capability. Protected MobileGestalt mutation remains unavailable
until a real primitive has been validated against the harmless canary.
