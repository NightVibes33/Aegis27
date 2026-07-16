# iOS 27 beta 3 service analysis

## Scope

This phase replaces blind path guessing with evidence-driven service research.
It correlates the public `24A5370h` to `24A5380h` firmware diff with read-only
runtime policy and bootstrap lookup measurements on `iPhone17,3`.

The public diff was generated from `iPhone18,1`. Userland findings are treated
as candidates until the target device confirms the corresponding service or
policy behavior.

## Ranked findings

### 1. MobileAsset

The beta-3 `mobileassetd` sandbox profile changed path predicates used by
`file-issue-extension` rules for multiple extension classes. A stock
`com.apple.mobileassetd` port resolves on the target. This makes MobileAsset the
strongest current interface candidate, but lookup and a send right do not prove
that an unprivileged client can request or receive an extension.

### 2. bookassetd

The beta-3 daemon gained:

- `platform-application`
- the embedded `temporary-sandbox` profile
- protected MobileGestalt keys
- new home-relative read/write exceptions
- a per-process temporary-directory suffix

The previously tested `com.apple.bookassetd` name does not resolve from the app.
The firmware diff does not establish the daemon's external listener name.

### 3. Backup, CacheDelete, FileProvider, and AFC

MobileBackup mount rules, CacheDelete app-container matching, and afcd extension
issuance rules changed. The corresponding bounded service-name candidates are
now included in the runtime inventory. A lookup test sends no protocol message
and immediately releases any acquired port.

## Interpretation rules

- `sandbox_check == 0`: policy permits the lookup operation; it does not prove
  that launchd registered the service.
- bootstrap lookup success: the app received an ordinary send right; it does
  not prove the service accepts a request.
- protected metadata visibility: not protected file-data access.
- `ENOENT`: missing path, not permission denial.
- only a successful protected read or controlled create-and-delete advances the
  filesystem capability result.

## Reproducibility

Run `scripts/index_beta3_service_diff.sh` against the public Blacktop directory
`27_0_24A5370h_vs_27_0_24A5380h`, or use the
`Index iOS 27 beta 3 file-service changes` GitHub Actions workflow.
