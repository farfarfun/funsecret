#!/usr/bin/env bash
# 把一个已经构建好的静态二进制打成 .deb。
#
#   build-deb.sh <二进制> <版本号> <amd64|arm64> [输出目录]
#
# 只接受 musl 静态二进制 —— control 里没有 Depends。
set -euo pipefail

BIN="${1:-}"
VERSION="${2:-}"
ARCH="${3:-}"
OUTPUT_DIR="${4:-dist}"

die() {
  echo "错误: $*" >&2
  exit 1
}

[[ -f "$BIN" ]] || die "给的二进制不存在: ${BIN:-<空>}"
VERSION="${VERSION#v}"
[[ -n "$VERSION" && "$VERSION" =~ ^[0-9][0-9A-Za-z.+:~-]*$ ]] || die "版本号无效: ${VERSION:-<空>}"
case "$ARCH" in
  amd64 | arm64) ;;
  *) die "架构只认 amd64 / arm64，给的是: ${ARCH:-<空>}" ;;
esac
command -v dpkg-deb >/dev/null 2>&1 || die "缺少 dpkg-deb"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf -- "$WORK"' EXIT
STAGE="${WORK}/root"

install -D -m 0755 "$BIN" "${STAGE}/usr/bin/funsecret"
install -D -m 0644 "${ROOT}/LICENSE" "${STAGE}/usr/share/doc/funsecret/copyright"

INSTALLED_SIZE="$(du -sk "${STAGE}/usr" | awk '{print $1}')"
mkdir -p "${STAGE}/DEBIAN"
cat >"${STAGE}/DEBIAN/control" <<EOF
Package: funsecret
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: ${ARCH}
Maintainer: farfarfun <farfarfun@qq.com>
Installed-Size: ${INSTALLED_SIZE}
Homepage: https://github.com/farfarfun/funsecret
Description: Local-first encrypted secret manager CLI with SQLite and database sync
 funsecret stores encrypted credentials locally in SQLite3 with 2-5 level
 category paths and syncs across SQLite3, MySQL/MariaDB, and PostgreSQL databases.
 Statically linked; no runtime dependencies.
EOF

PACKAGE="${OUTPUT_DIR}/funsecret_${VERSION}_${ARCH}.deb"
dpkg-deb --root-owner-group --build "${STAGE}" "${PACKAGE}" >/dev/null
echo "$PACKAGE"
