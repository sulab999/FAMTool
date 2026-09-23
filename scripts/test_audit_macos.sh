#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$ROOT/target/audit"
xcrun clang -fobjc-arc -fblocks -O1 -Wall -Wextra -Werror -mmacosx-version-min=11.0 \
  "$ROOT/native/audit/test_encoder.m" -framework Foundation -framework Security -framework SystemConfiguration -lEndpointSecurity -lbsm -o "$ROOT/target/audit/test-encoder"
"$ROOT/target/audit/test-encoder"
xcrun clang -fobjc-arc -fblocks -O1 -Wall -Wextra -Werror -mmacosx-version-min=11.0 \
  "$ROOT/native/audit/test_service_bridge.m" -framework Foundation -framework AppKit -framework Security -framework ServiceManagement -o "$ROOT/target/audit/test-service-bridge"
"$ROOT/target/audit/test-service-bridge"
