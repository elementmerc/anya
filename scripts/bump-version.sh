#!/usr/bin/env bash
# bump-version.sh — Update version in all 4 files, commit, and tag.
#
# Usage:
#   ./scripts/bump-version.sh 1.3.0
#   ./scripts/bump-version.sh 1.3.0 --tag    # also creates git tag

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <version> [--tag]"
  echo "Example: $0 1.3.0"
  echo "         $0 1.3.0 --tag"
  exit 1
fi

VERSION="$1"
CREATE_TAG="${2:-}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Validate version format
if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$ ]]; then
  echo "Error: Invalid version format '$VERSION'. Expected: X.Y.Z or X.Y.Z-beta.1"
  exit 1
fi

echo "Bumping version to ${VERSION} in:"

# 1. Cargo.toml (workspace root)
sed -i "s/^version = \"[^\"]*\"/version = \"${VERSION}\"/" "${REPO_ROOT}/Cargo.toml"
echo "  - Cargo.toml"

# 2. src-tauri/Cargo.toml
sed -i "s/^version = \"[^\"]*\"/version = \"${VERSION}\"/" "${REPO_ROOT}/src-tauri/Cargo.toml"
echo "  - src-tauri/Cargo.toml"

# 3. src-tauri/tauri.conf.json
sed -i "s/\"version\": \"[^\"]*\"/\"version\": \"${VERSION}\"/" "${REPO_ROOT}/src-tauri/tauri.conf.json"
echo "  - src-tauri/tauri.conf.json"

# 4. package.json
sed -i "s/\"version\": \"[^\"]*\"/\"version\": \"${VERSION}\"/" "${REPO_ROOT}/package.json"
echo "  - package.json"

# Verify
echo ""
echo "Verification:"
grep -n "^version" "${REPO_ROOT}/Cargo.toml" | head -1
grep -n "^version" "${REPO_ROOT}/src-tauri/Cargo.toml" | head -1
grep -n '"version"' "${REPO_ROOT}/src-tauri/tauri.conf.json" | head -1
grep -n '"version"' "${REPO_ROOT}/package.json" | head -1

if [[ "$CREATE_TAG" == "--tag" ]]; then
  echo ""
  git -C "${REPO_ROOT}" add Cargo.toml src-tauri/Cargo.toml src-tauri/tauri.conf.json package.json
  git -C "${REPO_ROOT}" commit -m "Bump version to ${VERSION}"
  git -C "${REPO_ROOT}" tag "v${VERSION}"
  echo "Committed and tagged v${VERSION}"
  echo "Push with: git push && git push --tags"
else
  echo ""
  echo "Files updated. To commit and tag:"
  echo "  git add Cargo.toml src-tauri/Cargo.toml src-tauri/tauri.conf.json package.json"
  echo "  git commit -m 'Bump version to ${VERSION}'"
  echo "  git tag v${VERSION}"
  echo "  git push && git push --tags"
fi
