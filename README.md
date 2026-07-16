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
