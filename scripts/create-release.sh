#!/usr/bin/env bash
#
# Set the Axeno relay version everywhere it matters, in one shot:
#
#   ./scripts/set-version.sh 0.2.0
#
# Updates Cargo.toml and Cargo.lock. It does NOT create the git tag. Review the
# diff, commit, then:
#
#   git tag v<version> && git push origin v<version>
#
# The tag must match the version set here: the opt-in update check
# (AXENO_UPDATE_CHECK) compares the running binary's CARGO_PKG_VERSION against
# the latest release tag by semver, so a mismatched tag misreports updates.
set -euo pipefail

cd "$(dirname "$0")/.."

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
  echo "usage: $0 <version>   (e.g. $0 0.2.0)" >&2
  exit 1
fi
if ! printf '%s' "$VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$'; then
  echo "error: '$VERSION' is not a valid semver version" >&2
  exit 1
fi

echo "==> Cargo.toml + Cargo.lock"
# Replace only the [package] version line (the first `version = ` in the file).
sed -i.bak -E "0,/^version = \"[^\"]*\"/s//version = \"$VERSION\"/" Cargo.toml
rm -f Cargo.toml.bak
cargo update --package axeno-relay --offline --quiet

echo
echo "Version set to $VERSION in Cargo.toml and Cargo.lock."
echo
echo "Next: review the diff, commit, then tag the release:"
echo "  git tag v$VERSION && git push origin v$VERSION"
