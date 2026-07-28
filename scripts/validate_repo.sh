#!/usr/bin/env bash
set -euo pipefail

required=(
  project.yml
  Resources/Info.plist
  Resources/Aegis27.entitlements
  App/Aegis27App.swift
  Models/BoundaryLabModels.swift
  Models/BoundaryTransportModels.swift
  Models/CrashTriageModels.swift
  Models/PatchDiffModels.swift
  Services/BoundaryLabService.swift
  Services/BoundaryTransportCoordinator.swift
  Services/CrashTriageService.swift
  Services/PatchDiffRequestService.swift
  ViewModels/CrashTriageViewModel.swift
  ViewModels/PatchDiffViewModel.swift
  Views/BoundaryLabView.swift
  Views/BoundaryTransportView.swift
  Views/CrashTriageView.swift
  Views/PatchDiffLabView.swift
  CanaryBox/CanaryBoxApp.swift
  CanaryBox/CanaryModels.swift
  CanaryBox/CanaryStore.swift
  CanaryBox/CanaryTransport.swift
  CanaryBox/Info.plist
  AegisShareExtension/ShareViewController.swift
  AegisShareExtension/Info.plist
  Views/ContentView.swift
  docs/CRASH_TRIAGE.md
  docs/PATCH_DIFF_LAB.md
  .github/workflows/build-unsigned-ipa.yml
  .github/workflows/cloud-firmware-lab.yml
  .github/workflows/ipsw-patch-diff.yml
  scripts/cloud_firmware_lab.py
  scripts/patch_diff_lab.py
  scripts/analyze_device_report.py
  .github/workflows/device-report-bridge.yml
)

for path in "${required[@]}"; do
  test -f "$path" || { echo "Missing $path" >&2; exit 1; }
done

python3 -m unittest tests/test_cloud_firmware_lab.py
python3 -m unittest tests/test_analyze_device_report.py
python3 -m unittest tests/test_patch_diff_lab.py
python3 -m py_compile scripts/patch_diff_lab.py
/usr/bin/plutil -lint \
  Resources/Info.plist \
  CanaryBox/Info.plist \
  AegisShareExtension/Info.plist >/dev/null

if grep -R --line-number -E 'platform-application|com\.apple\.private|task_for_pid-allow|get-task-allow' Resources CanaryBox AegisShareExtension; then
  echo "Private or unsafe entitlement found" >&2
  exit 1
fi

if grep -R --line-number -E 'com\.apple\.security\.application-groups|keychain-access-groups' Resources CanaryBox AegisShareExtension; then
  echo "Shared App Group or Keychain access group found" >&2
  exit 1
fi

if grep -R --line-number --include='*.swift' -E 'removeItem\(atPath:|truncateFile|O_TRUNC' Services AegisShareExtension; then
  echo "Potentially destructive filesystem operation found" >&2
  exit 1
fi

# Crash triage must remain limited to Aegis-owned Application Support files and public parser APIs.
grep -q 'AegisCrashTriage' Services/CrashTriageService.swift
grep -q 'maximumCorpusBytes = 4 \* 1024 \* 1024' Services/CrashTriageService.swift
grep -q 'CGImageSourceCreateThumbnailAtIndex' Services/CrashTriageService.swift
grep -q 'pending-case.json' Services/CrashTriageService.swift
grep -q 'minimizationSessionID' Models/CrashTriageModels.swift

# Patch diff is static comparison only: strict request fields, allow-listed ipsw flags, and no payload generation.
grep -q 'KIND = "ipsw-patch-diff"' scripts/patch_diff_lab.py
grep -q 'SURFACE_FLAGS' scripts/patch_diff_lab.py
grep -q 'static-review-candidate' scripts/patch_diff_lab.py
grep -q 'ipsw --no-color diff' .github/workflows/ipsw-patch-diff.yml
grep -q -- '--sandbox' scripts/patch_diff_lab.py
grep -q -- '--starts' scripts/patch_diff_lab.py
grep -q -- '--strs' scripts/patch_diff_lab.py
grep -q "kind != 'ipsw-patch-diff'" .github/workflows/device-report-bridge.yml
if grep -R --line-number -E 'panicPayload|exploitPayload|trustCachePatch|sandboxEscapePayload' Models/PatchDiffModels.swift Services/PatchDiffRequestService.swift ViewModels/PatchDiffViewModel.swift Views/PatchDiffLabView.swift scripts/patch_diff_lab.py; then
  echo "Patch-diff code must not contain exploit or panic payload generation" >&2
  exit 1
fi

grep -q 'PRODUCT_BUNDLE_IDENTIFIER: com.nightvibes33.Aegis27.v08' project.yml
grep -q 'PRODUCT_BUNDLE_IDENTIFIER: com.nightvibes33.CanaryBox' project.yml
grep -q 'PRODUCT_BUNDLE_IDENTIFIER: com.nightvibes33.Aegis27.v08.BoundaryShare' project.yml
grep -q 'MARKETING_VERSION: 0.19.0' project.yml
grep -q 'CURRENT_PROJECT_VERSION: 18' project.yml
grep -q 'canarybox-boundary' CanaryBox/Info.plist
grep -q 'aegis27-boundary' Resources/Info.plist
grep -q 'com.nightvibes33.canarybox.boundary-envelope' Resources/Info.plist
grep -q 'com.nightvibes33.canarybox.boundary-envelope' CanaryBox/Info.plist
grep -q 'Aegis27-unsigned.ipa' .github/workflows/build-unsigned-ipa.yml
grep -q 'CanaryBox-unsigned.ipa' .github/workflows/build-unsigned-ipa.yml

echo "Repository safety checks passed."
