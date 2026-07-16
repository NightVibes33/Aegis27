#!/usr/bin/env bash
set -euo pipefail

required=(
  project.yml
  Resources/Info.plist
  Resources/Aegis27.entitlements
  App/Aegis27App.swift
  Views/ContentView.swift
  .github/workflows/build-unsigned-ipa.yml
  .github/workflows/cloud-firmware-lab.yml
  scripts/cloud_firmware_lab.py
  scripts/analyze_device_report.py
  .github/workflows/device-report-bridge.yml
)

for path in "${required[@]}"; do
  test -f "$path" || { echo "Missing $path" >&2; exit 1; }
done

python3 -m unittest tests/test_cloud_firmware_lab.py
python3 -m unittest tests/test_analyze_device_report.py

if grep -R --line-number -E 'platform-application|com\.apple\.private|task_for_pid-allow|get-task-allow' Resources; then
  echo "Private or unsafe entitlement found" >&2
  exit 1
fi

if grep -R --line-number --include='*.swift' -E 'removeItem\(atPath:|truncateFile|O_TRUNC' Services; then
  echo "Potentially destructive filesystem operation found" >&2
  exit 1
fi

echo "Repository safety checks passed."
