#!/usr/bin/env bash
set -euo pipefail

TAG="preserve/integration-2025-08-26"
TITLE="PRF support + Integration Snapshot (2025-08-26)"
BODY_FILE="docs/releases/2025-08-26-prf-support.md"

if ! command -v gh >/dev/null 2>&1; then
  echo "gh CLI not found. Install from https://cli.github.com/ or use GitHub UI."
  exit 1
fi

# Create or update a draft release
if gh release view "$TAG" >/dev/null 2>&1; then
  gh release edit "$TAG" --title "$TITLE" --notes-file "$BODY_FILE" --draft
else
  gh release create "$TAG" --title "$TITLE" --notes-file "$BODY_FILE" --draft
fi

# Upload assets
ASSETS=(
  backups/integration-2025-08-26.zip
  backups/feat-prf-support-2025-08-26.bundle
  backups/main-integration-2025-08-26.bundle
)
for a in "${ASSETS[@]}"; do
  gh release upload "$TAG" "$a" --clobber
done

echo "Draft release prepared for tag $TAG"
