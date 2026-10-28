#!/bin/sh
# Packages release binaries from target/release into dist/:
#   acf-<version>-<target>.tar.gz and its .sha256.
# Usage: scripts/package-release.sh <version> [target-triple]
set -eu

version=$1
target=${2:-x86_64-unknown-linux-gnu}
name="acf-$version-$target"
stage="dist/$name"

if [ -e "$stage" ]; then
    echo "$stage already exists" >&2
    exit 1
fi
mkdir -p "$stage/bin" "$stage/docs" "$stage/examples"

for binary in acf-gateway acf-store acf-setup acf-control-plane acf-agent; do
    install -m 0755 "target/release/$binary" "$stage/bin/$binary"
done

# A development build offers --secret-env and the in-memory provider; a
# release artifact must not.
if "$stage/bin/acf-gateway" --help | grep -q -- '--secret-env'; then
    echo "target/release/acf-gateway is a development build" >&2
    exit 1
fi
for binary in acf-gateway acf-store acf-setup acf-control-plane acf-agent; do
    "$stage/bin/$binary" --version | grep -q -- "$version" || {
        echo "$binary does not report version $version" >&2
        exit 1
    }
done

# The supported floor is Ubuntu 20.04 (glibc 2.31). A binary built on a newer
# distribution can need newer glibc symbols and fail to start there.
max_glibc=2.31
for binary in acf-gateway acf-store acf-setup acf-control-plane acf-agent; do
    needed=$(objdump -T "$stage/bin/$binary" | grep -oE 'GLIBC_[0-9]+(\.[0-9]+)+' \
        | sed 's/^GLIBC_//' | sort -Vu | tail -1)
    if [ "$(printf '%s\n%s\n' "$needed" "$max_glibc" | sort -V | tail -1)" != "$max_glibc" ]; then
        echo "$binary needs glibc $needed; the floor is $max_glibc (build on Ubuntu 20.04)" >&2
        exit 1
    fi
done

cp README.md "$stage/"
cp "docs/releases/v$version.md" "$stage/RELEASE-NOTES.md" 2>/dev/null \
    || cp docs/releases/v1.0.0.md "$stage/RELEASE-NOTES.md"
cp docs/deployment.md docs/mcp.md docs/staging.md "$stage/docs/"
cp docs/security/v1-review.md "$stage/docs/security-review.md"
cp -R examples/cloudflare-readonly "$stage/examples/"
if [ -f LICENSE ]; then
    cp LICENSE "$stage/"
fi

tar -C dist -czf "dist/$name.tar.gz" "$name"
(cd dist && sha256sum "$name.tar.gz" > "$name.tar.gz.sha256")
echo "dist/$name.tar.gz"
