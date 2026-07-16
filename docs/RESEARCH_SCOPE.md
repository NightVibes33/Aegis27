# Authorized research scope

Target owner: Bobby Tatum

Primary test device: personally owned `iPhone17,3` (iPhone 16). The harness is
not model-locked and may collect the same non-destructive baseline on other
devices.

The stock file provider may browse only locations available to an ordinary
sandboxed application. The escaped provider is an inert integration boundary.
Personal-data targets are excluded by default and inventory only metadata when
explicitly enabled.

Target software: iOS 27 developer beta 3, build `24A5380h`

Purpose: good-faith vulnerability research, controlled proof-of-concept
validation, remediation research, and responsible disclosure.

## Guardrails

- Do not run against third-party devices or data.
- Do not add persistence, credential access, surveillance, or remote delivery.
- Do not claim a primitive works without device logs demonstrating it.
- Use uniquely named canary files; never overwrite unknown files.
- Back up the test device before mutation testing.
- Record the complete build number with every result.
- Report newly discovered Apple vulnerabilities through Apple's security
  reporting process before public operational release.
