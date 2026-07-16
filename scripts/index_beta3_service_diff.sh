#!/usr/bin/env bash
set -euo pipefail

diff_root="${1:?usage: index_beta3_service_diff.sh DIFF_ROOT OUTPUT_DIR}"
output_dir="${2:?usage: index_beta3_service_diff.sh DIFF_ROOT OUTPUT_DIR}"

test -f "$diff_root/README.md"
test -f "$diff_root/Entitlements.md"
mkdir -p "$output_dir/evidence"

files=(
  "README.md"
  "Entitlements.md"
  "SANDBOX/Collection/afcd.md"
  "SANDBOX/Collection/CacheDeleteAppContainerCaches.md"
  "SANDBOX/Collection/MobileBackup.md"
  "SANDBOX/Collection/mobileassetd.md"
  "MACHOS/filesystem/System/Library/PrivateFrameworks/BookLibraryCore.framework/Support/bookassetd.md"
  "MACHOS/filesystem/System/Library/PrivateFrameworks/MobileBackup.framework/backupd.md"
  "MACHOS/filesystem/System/Library/PrivateFrameworks/CacheDelete.framework/deleted.md"
  "MACHOS/filesystem/usr/libexec/mobileassetd.md"
)

for relative in "${files[@]}"; do
  source_path="$diff_root/$relative"
  if test -f "$source_path"; then
    destination="$output_dir/evidence/$relative"
    mkdir -p "$(dirname "$destination")"
    cp "$source_path" "$destination"
  fi
done

rg -n -i \
  'file-issue-extension|temporary-sandbox|platform-application|MobileContainerManager|MobileGestalt|absolute-path|home-relative-path|file-mount|app.container|sandbox.extension|mobileassetd|bookassetd|backupd|CacheDelete|FileProvider|afcd' \
  "$output_dir/evidence" > "$output_dir/focused-index.txt" || true

cat > "$output_dir/SUMMARY.md" <<'EOF'
# iOS 27 beta 3 service-focused firmware index

Input diff: iOS 27 beta 2 `24A5370h` to beta 3 `24A5380h`.

The public upstream diff uses `iPhone18,1`. These userland service and sandbox
changes are candidates for validation on `iPhone17,3`; they are not proof that
every device has identical binaries and they are not proof of a sandbox escape.

## Ranked observations

1. `mobileassetd`: its sandbox profile changed the path predicates used while
   issuing several sandbox-extension classes. The stock service is reachable on
   the measured `iPhone17,3` target.
2. `bookassetd`: gained `platform-application`, `temporary-sandbox`, protected
   MobileGestalt access, and additional filesystem exceptions. The external
   listener name is not established by this diff.
3. MobileBackup and CacheDelete: mount and app-container cache matching rules
   changed. Treat these as secondary until a related service resolves on target.
4. `afcd`: extension issuance rules changed, but the ordinary app sandbox does
   not currently resolve the bounded AFC listener candidates.

`focused-index.txt` contains exact matching lines and paths. The copied evidence
files preserve the upstream generated diff for review.
EOF

printf 'Indexed %s evidence files\n' "$(find "$output_dir/evidence" -type f | wc -l | tr -d ' ')"
