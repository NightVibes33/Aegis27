# Aegis27

Aegis27 is an iOS 27 research harness for a personally owned iPhone 16
(`iPhone17,3`) running build `24A5380h`. It establishes a reproducible baseline for MobileGestalt reads,
strict-folder capability probes, one-shot write canaries, device/build locking,
and structured evidence collection.

## Current status

**This is not currently a jailbreak.** The initial version intentionally does
not contain a sandbox escape, kernel exploit, PPL bypass, code-signing bypass,
or persistence mechanism. It provides a safe and testable place to integrate a
privileged primitive only after that primitive has been independently validated
on the exact target build.

## Safety behavior

- Mutation testing is locked to `iPhone17,3` on iOS 27 build `24A5380h`.
- The exported log includes MobileGestalt values and syscall-level sandbox
  policy decisions for candidate paths and Mach services.
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

## Next research milestone

Capture the complete iOS beta build number from the app, export the baseline
JSONL log, and validate candidate primitives against a harmless canary before
allowing any MobileGestalt cache mutation.
