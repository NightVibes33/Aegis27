# Cloud firmware lab

This component moves firmware-side static analysis to a GitHub-hosted macOS
runner so the device owner does not need a Mac. It does not run against the
connected iPhone and it does not alter firmware.

## Running it

1. Open the repository's **Actions** page.
2. Select **Build cloud firmware probe catalog**.
3. Choose **Run workflow**.
4. Enter the hardware identifier and exact build shown by Aegis27.
5. When the job finishes, download the artifact named
   `Aegis27-firmware-lab-<device>-<build>`.
6. Extract the artifact and import `aegis27-probe-catalog.json` in the app's
   Attack Surface screen.

For the current research target, the inputs are `iPhone17,3` and `24A5380h`.

## What it establishes

The analyzer maps launchd `MachServices` declarations to the corresponding
`Program` executable. For each extracted Mach-O it records:

- file size and SHA-256;
- XPC API-name evidence;
- candidate dictionary-key strings;
- entitlement key names, but not entitlement values;
- bounded Objective-C selector and Swift-symbol inventories;
- referenced Uniform Type Identifiers; and
- candidate IOKit class names.

It also records hashes and sizes for extracted sandbox-profile files. The
evidence report retains provenance separately from the compact catalog.

## Important limits

Static analysis cannot prove an XPC schema or a security defect. Compilers can
separate key strings from the code paths that consume them, services can apply
entitlement checks after accepting a connection, and many implementations live
inside the dyld shared cache. Consequently:

- catalog fields are hypotheses;
- every request value is a fixed inert marker;
- the app repeats observations and correlates diagnostics;
- a reply or daemon restart is only a lead; and
- only the protected-file or foreign-container oracle confirms controlled
  sandbox impact.

The workflow extracts a maximum number of launchd-referenced programs and the
analyzer enforces per-file and aggregate byte budgets. Its uploaded artifact
contains reports and checksums only—never the IPSW or extracted executables.

## Device-report return channel

The separate `device-report-bridge.yml` workflow is triggered automatically by
the installed app after its one-time Keychain connection. Reports are staged
as assets on an unpublished draft release, analyzed on `ubuntu-latest`, and
replaced with a compact result that the app downloads. Source assets are
deleted after successful processing; result assets are deleted after the app
has saved them locally. No private repository is required.
