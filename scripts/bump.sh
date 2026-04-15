#!/usr/bin/env bash
# Bump locke version, rebuild dist, and optionally publish to GitLab.
# Usage: ./scripts/bump.sh [patch|minor|major]  (default: patch)
set -euo pipefail

PART="${1:-patch}"
PYPROJECT="python/pyproject.toml"
DIST_DIR="dist"

cd "$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"

# --- read current version ---------------------------------------------------
CURRENT=$(grep -Po '(?<=^version = ")[^"]+' "$PYPROJECT")
IFS='.' read -r MAJOR MINOR PATCH <<< "$CURRENT"

case "$PART" in
  major) MAJOR=$((MAJOR + 1)); MINOR=0; PATCH=0 ;;
  minor) MINOR=$((MINOR + 1)); PATCH=0 ;;
  patch) PATCH=$((PATCH + 1)) ;;
  *)     echo "Usage: $0 [patch|minor|major]"; exit 1 ;;
esac

NEXT="${MAJOR}.${MINOR}.${PATCH}"

# --- update pyproject.toml ---------------------------------------------------
sed -i "s/^version = \"${CURRENT}\"/version = \"${NEXT}\"/" "$PYPROJECT"
echo "Bumped $CURRENT -> $NEXT"

# --- rebuild -----------------------------------------------------------------
rm -f "$DIST_DIR"/locke-*.whl "$DIST_DIR"/locke-*.tar.gz
uv build --directory python --out-dir "$DIST_DIR"

echo ""
echo "Built: $(ls "$DIST_DIR"/locke-${NEXT}*)"
echo ""
echo "To publish:  uv publish --index locke-gitlab $DIST_DIR/locke-${NEXT}*"
echo "To commit:   git add $PYPROJECT $DIST_DIR && git commit -m 'Bump locke to $NEXT'"
