#!/usr/bin/env bash
# Release script for locke (Python package).
#
# Usage:
#   ./scripts/release.sh patch   # 0.1.0 -> 0.1.1
#   ./scripts/release.sh minor   # 0.1.0 -> 0.2.0
#   ./scripts/release.sh major   # 0.1.0 -> 1.0.0
#
# What it does:
#   1. Bumps the version in python/pyproject.toml
#   2. Commits the bump
#   3. Merges the current branch into main
#   4. Tags main with vX.Y.Z
#   5. Pushes main + tag (CI publishes to PyPI + GitLab registry)
#   6. Switches back to dev
set -euo pipefail

BUMP="${1:-}"
if [[ ! "$BUMP" =~ ^(patch|minor|major)$ ]]; then
  echo "Usage: $0 <patch|minor|major>"
  exit 1
fi

PYPROJECT="python/pyproject.toml"

# Must be on dev branch
BRANCH=$(git branch --show-current)
if [[ "$BRANCH" != "dev" ]]; then
  echo "Error: must be on the dev branch (currently on '$BRANCH')"
  exit 1
fi

# Working tree must be clean
if [[ -n "$(git status --porcelain)" ]]; then
  echo "Error: working tree is dirty — commit or stash changes first"
  exit 1
fi

# Read current version
CURRENT=$(python -c "import tomllib; print(tomllib.load(open('${PYPROJECT}','rb'))['project']['version'])")
IFS='.' read -r MAJOR MINOR PATCH_NUM <<< "$CURRENT"

case "$BUMP" in
  major) MAJOR=$((MAJOR + 1)); MINOR=0; PATCH_NUM=0 ;;
  minor) MINOR=$((MINOR + 1)); PATCH_NUM=0 ;;
  patch) PATCH_NUM=$((PATCH_NUM + 1)) ;;
esac

NEW_VERSION="${MAJOR}.${MINOR}.${PATCH_NUM}"
TAG="v${NEW_VERSION}"

echo "Bumping $CURRENT -> $NEW_VERSION"

# Bump version in pyproject.toml
sed -i "s/^version = \".*\"/version = \"${NEW_VERSION}\"/" "$PYPROJECT"
git add "$PYPROJECT"
git commit -m "Bump version to ${NEW_VERSION}"

# Merge into main and tag
git checkout main
git merge dev --no-edit
git tag -a "$TAG" -m "Release ${TAG}"

# Push
git push origin main "$TAG"

# Back to dev and fast-forward
git checkout dev
git merge main --ff-only

echo ""
echo "Released ${TAG} — CI will publish to PyPI and GitLab registry."
