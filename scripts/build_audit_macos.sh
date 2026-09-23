#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/target/audit/famtool-audit}"
mkdir -p "$(dirname "$OUT")"
# 跟随 cargo 目标架构(CARGO_CFG_TARGET_ARCH 由 build 脚本环境注入),交叉编译时保持一致
ARCH_ARGS=()
case "${CARGO_CFG_TARGET_ARCH:-$(uname -m)}" in
    x86_64) ARCH_ARGS=(-arch x86_64) ;;
    aarch64) ARCH_ARGS=(-arch arm64) ;;
esac
xcrun clang -fobjc-arc -fblocks -O2 -Wall -Wextra -Werror -mmacosx-version-min=11.0 \
  "${ARCH_ARGS[@]}" \
  "$ROOT/native/audit/main.m" -framework Foundation -framework Security -framework SystemConfiguration -lEndpointSecurity -lbsm -o "$OUT"
if [ -n "${WJ_AUDIT_SIGN_IDENTITY:-}" ]; then
    codesign --force --identifier com.famtool.audit --options runtime --sign "$WJ_AUDIT_SIGN_IDENTITY" --entitlements "$ROOT/native/audit/entitlements.plist" "$OUT"
else
    # Deliberately do not forge a restricted entitlement onto an ad-hoc binary.
    codesign --force --identifier com.famtool.audit --sign - "$OUT"
fi
codesign --verify --strict "$OUT"
