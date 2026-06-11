#!/usr/bin/env bash
#
# Cut a new Axeno relay release in one shot:
#
#   ./scripts/create-release.sh 0.2.0
#
# This sets the version, commits the bump, creates the v<version> tag, and
# pushes the branch + tag to origin. Pushing the tag triggers the GitHub
# release workflow, which builds the relay binaries into a DRAFT release for you
# to review and publish.
#
# Version is set in Cargo.toml and Cargo.lock.
#
# The tag must match the version set here: the opt-in update check
# (AXENO_UPDATE_CHECK) compares the running binary's CARGO_PKG_VERSION against
# the latest release tag by semver, so a mismatched tag misreports updates.
#
# Assumptions: the local checkout is already synced with origin and the working
# tree is clean. Pass -y / --yes to skip the confirmation prompt.
set -euo pipefail

cd "$(dirname "$0")/.."

VERSION=""
ASSUME_YES=0
for arg in "$@"; do
  case "$arg" in
    -y|--yes) ASSUME_YES=1 ;;
    -h|--help)
      echo "usage: $0 <version> [-y]   (e.g. $0 0.2.0)"
      exit 0 ;;
    -*) echo "error: unknown option '$arg'" >&2; exit 1 ;;
    *)
      if [ -n "$VERSION" ]; then echo "error: unexpected argument '$arg'" >&2; exit 1; fi
      VERSION="$arg" ;;
  esac
done

if [ -z "$VERSION" ]; then
  echo "usage: $0 <version> [-y]   (e.g. $0 0.2.0)" >&2
  exit 1
fi
if ! printf '%s' "$VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$'; then
  echo "error: '$VERSION' is not a valid semver version" >&2
  exit 1
fi
case "$VERSION" in
  *-*)
    echo "WARN: '$VERSION' is a prerelease. Semver orders it BEFORE the bare version" >&2
    echo "WARN: (0.2.0-beta < 0.2.0), which is what the update check compares by." >&2
    ;;
esac

TAG="v$VERSION"

# ── Pre-flight git checks ──────────────────────────────────────────────────
if ! git rev-parse --git-dir >/dev/null 2>&1; then
  echo "error: not inside a git repository" >&2
  exit 1
fi
BRANCH="$(git rev-parse --abbrev-ref HEAD)"
if [ -n "$(git status --porcelain)" ]; then
  echo "error: working tree is not clean. Commit, stash, or discard changes first." >&2
  echo "       This script commits only the version bump, so the tree must start clean." >&2
  exit 1
fi
if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
  echo "error: tag $TAG already exists locally. Pick a new version or delete the tag." >&2
  exit 1
fi
if git ls-remote --exit-code --tags origin "refs/tags/$TAG" >/dev/null 2>&1; then
  echo "error: tag $TAG already exists on origin. Pick a new version." >&2
  exit 1
fi

echo "About to release $TAG:"
echo "  - set version to $VERSION in Cargo.toml + Cargo.lock"
echo "  - commit the bump on branch '$BRANCH'"
echo "  - create annotated tag $TAG"
echo "  - push '$BRANCH' and $TAG to origin (this triggers the release build)"
echo
if [ "$ASSUME_YES" -ne 1 ]; then
  printf "Proceed? [y/N] "
  read -r reply
  case "$reply" in
    [yY]|[yY][eE][sS]) ;;
    *) echo "aborted."; exit 1 ;;
  esac
fi

echo "==> Cargo.toml + Cargo.lock"
# Replace only the [package] version line (the first `version = ` in the file).
sed -i.bak -E "0,/^version = \"[^\"]*\"/s//version = \"$VERSION\"/" Cargo.toml
rm -f Cargo.toml.bak
cargo update --package axeno-relay --offline --quiet

echo "==> committing version bump"
git add -A
if git diff --cached --quiet; then
  echo "    (files already at $VERSION; tagging the current commit)"
else
  git commit -m "release $TAG" >/dev/null
fi

echo "==> creating tag $TAG"
git tag -a "$TAG" -m "Axeno relay $TAG"

echo "==> pushing branch '$BRANCH' and tag $TAG"
git push origin "$BRANCH"
git push origin "$TAG"

echo
echo "Done. $TAG is pushed; the release workflow is building."
echo "It publishes a DRAFT release — review and publish it so setup-relay.* can"
echo "fetch the new binaries:"
echo "  https://github.com/axenochat/axeno-relay/releases"
