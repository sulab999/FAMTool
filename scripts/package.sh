#!/usr/bin/env bash
# FAMTool 全平台打包脚本 —— 一键生成 dist/ 下的安装程序:
#   macOS  : FAMTool_*_macos_{aarch64,x86_64}.dmg
#   Windows: FAMTool_*_x64-setup.exe            (NSIS,交叉构建)
#   Linux  : FAMTool_*.deb / FAMTool-*.rpm      (Docker 容器内构建,双架构)
#
# 用法:
#   ./scripts/package.sh                       # 全部平台(缺依赖的平台跳过并提示)
#   ./scripts/package.sh macos                 # 仅 macOS(本机+交叉双架构)
#   ./scripts/package.sh macos --target x86_64-apple-darwin   # 仅指定架构
#   ./scripts/package.sh windows               # 仅 Windows NSIS
#   ./scripts/package.sh linux                 # 仅 Linux(本机 Docker 架构)
#   ./scripts/package.sh linux --platform amd64               # 指定 Linux 架构
#
# 环境变量:
#   WJ_APP_SIGN_IDENTITY    macOS 开发者签名身份(默认 ad-hoc 签名)
#   WJ_AUDIT_SIGN_IDENTITY  审计辅助程序独立签名身份(默认跟随前者)
#   WJ_CARGO_JOBS           Linux 容器内编译并行度(默认 2,防 VM 内存不足)
#   WJ_CLEAN=1              清空 Linux 容器内编译缓存后重编
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
mkdir -p dist

ensure_node() {
    if [ ! -d node_modules/@tauri-apps/cli ]; then
        npm ci
    fi
}

# ---------------------------------------------------------------- macOS
build_macos() {
    if [ "$(uname)" != "Darwin" ]; then
        echo ">>> 跳过 macOS:只能在 macOS 上构建" >&2
        return 0
    fi
    local TARGET_ARGS=() TARGET="" ARCH_TAG ARCH_DIR
    ARCH_TAG="$(uname -m | sed 's/arm64/aarch64/')"
    ARCH_DIR="target/release"
    if [ "${1:-}" = "--target" ]; then
        shift
        TARGET="$1"; shift
        TARGET_ARGS=(--target "$TARGET")
        ARCH_TAG="${TARGET%%-*}"
        ARCH_DIR="target/$TARGET/release"
        rustup target add "$TARGET"
    fi

    ensure_node
    if [ -n "${WJ_APP_SIGN_IDENTITY:-}" ]; then
        export APPLE_SIGNING_IDENTITY="$WJ_APP_SIGN_IDENTITY"
        export WJ_AUDIT_SIGN_IDENTITY="${WJ_AUDIT_SIGN_IDENTITY:-$WJ_APP_SIGN_IDENTITY}"
    fi
    npm run build -- ${TARGET_ARGS[@]+"${TARGET_ARGS[@]}"} --bundles app

    local SOURCE="$ROOT/$ARCH_DIR/bundle/macos/FAMTool.app"
    if [ ! -d "$SOURCE" ]; then
        echo "未找到 Tauri 应用包: $SOURCE" >&2
        return 1
    fi
    cargo build -p famtool-cli --bin audit-pipe --release ${TARGET_ARGS[@]+"${TARGET_ARGS[@]}"}

    local APP_OUT="$ROOT/FAMTool.app"
    local HOST_ARCH="$(uname -m | sed 's/arm64/aarch64/')"
    if [ -n "$TARGET" ] && [ "$ARCH_TAG" != "$HOST_ARCH" ]; then
        # 交叉架构产物只进 dist/,不覆盖根目录的本机应用包
        APP_OUT="$ROOT/dist/FAMTool.app.$ARCH_TAG"
        rm -rf "$APP_OUT"
    fi
    ditto "$SOURCE" "$APP_OUT"
    # OpenBSM 审计辅助程序(管理员密码方式;无需 Apple 授权)
    cp "$ROOT/$ARCH_DIR/audit-pipe" "$APP_OUT/Contents/MacOS/audit-pipe"
    chmod 755 "$APP_OUT/Contents/MacOS/audit-pipe"
    rm -f "$APP_OUT/Contents/Resources/audit-helper"
    if [ -n "${WJ_APP_SIGN_IDENTITY:-}" ]; then
        # Keep the helper's restricted entitlement; sign the containing app last.
        codesign --force --options runtime --sign "$WJ_APP_SIGN_IDENTITY" "$APP_OUT"
    else
        codesign --force --deep --sign - "$APP_OUT"
    fi
    codesign --verify --deep --strict "$APP_OUT"

    # DMG 安装镜像(含应用与 /Applications 快捷方式)
    local VERSION STAGING DMG
    VERSION="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$APP_OUT/Contents/Info.plist" 2>/dev/null || echo "1.0.0")"
    DMG="$ROOT/dist/FAMTool_${VERSION}_macos_${ARCH_TAG}.dmg"
    STAGING="$(mktemp -d)"
    ditto "$APP_OUT" "$STAGING/FAMTool.app"
    ln -sf /Applications "$STAGING/Applications"
    hdiutil create -volname FAMTool -srcfolder "$STAGING" -ov -format UDZO -fs HFS+ "$DMG" >/dev/null
    rm -rf "$STAGING"
    echo ">>> 已生成 $DMG"
}

# ---------------------------------------------------------------- Windows
build_windows() {
    if ! command -v cargo-xwin >/dev/null 2>&1 || ! command -v makensis >/dev/null 2>&1; then
        echo ">>> 跳过 Windows:需要 cargo-xwin(cargo install cargo-xwin)与 NSIS(brew install nsis llvm)" >&2
        return 0
    fi
    ensure_node
    local LLVM_BIN
    LLVM_BIN="$(brew --prefix llvm 2>/dev/null)/bin"
    if [ -d "$LLVM_BIN" ]; then
        export PATH="$LLVM_BIN:$PATH"
    fi
    # 先清空打包输出目录,避免上次构建的旧文件混入 dist
    rm -rf target/x86_64-pc-windows-msvc/release/bundle/nsis
    npm run build -- --runner cargo-xwin --target x86_64-pc-windows-msvc --bundles nsis
    find target/x86_64-pc-windows-msvc/release/bundle/nsis -name "*_x64-setup.exe" \
        -exec cp -v {} dist/ \;
    echo ">>> Windows NSIS 安装程序已复制到 dist/"
}

# ---------------------------------------------------------------- Linux
build_linux() {
    if ! docker info >/dev/null 2>&1; then
        echo ">>> 跳过 Linux:需要运行中的 Docker(Docker Desktop)" >&2
        return 0
    fi
    local PLATFORM="linux/arm64" ARCH_TAG="aarch64"
    if [ "${1:-}" = "--platform" ]; then
        case "$2" in
            amd64) PLATFORM="linux/amd64"; ARCH_TAG="x86_64" ;;
            arm64) PLATFORM="linux/arm64"; ARCH_TAG="aarch64" ;;
            *) echo "不支持的架构: $2" >&2; return 1 ;;
        esac
        shift 2
    fi

    local IMAGE_TAG="famtool-linux-builder:${ARCH_TAG}"
    if ! docker image inspect "$IMAGE_TAG" >/dev/null 2>&1; then
        echo ">>> 构建 Docker 镜像 $IMAGE_TAG (首次较慢)..."
        if [ "$ARCH_TAG" = "x86_64" ]; then
            docker buildx build --platform "$PLATFORM" -f scripts/docker/Dockerfile.linux -t "$IMAGE_TAG" --load .
        else
            docker build -f scripts/docker/Dockerfile.linux -t "$IMAGE_TAG" .
        fi
    fi

    local UID_GID
    UID_GID="$(id -u):$(id -g)"
    echo ">>> 在容器内构建 Linux $ARCH_TAG 安装包 (deb,rpm)..."
    docker run --rm --platform "$PLATFORM" \
        -v "$ROOT":/work -w /work \
        -e CARGO_TARGET_DIR=/work/target-linux \
        -e CARGO_HOME=/usr/local/cargo \
        -e WJ_CLEAN="${WJ_CLEAN:-0}" \
        -e WJ_CARGO_JOBS="${WJ_CARGO_JOBS:-2}" \
        -v famtool-cargo-registry:/usr/local/cargo/registry \
        -v famtool-cargo-git:/usr/local/cargo/git \
        -v "famtool-target-linux-$ARCH_TAG:/work/target-linux" \
        "$IMAGE_TAG" \
        bash -c '
            set -euo pipefail
            # LTO 编译内存峰值高,VM 内限制并行度防止 OOM
            export CARGO_BUILD_JOBS="${WJ_CARGO_JOBS:-2}"
            # WJ_CLEAN=1 清理容器内编译缓存(VM 崩溃后可能留下损坏的增量产物)。
            # 不能用 cargo clean——它会尝试删除作为挂载点的 CARGO_TARGET_DIR 本身。
            if [ "${WJ_CLEAN:-0}" = "1" ]; then
                find "${CARGO_TARGET_DIR:?}" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
            fi
            # 打包输出目录随构建重生成,先清空避免上次构建的旧文件混入 dist
            rm -rf /work/target-linux/release/bundle
            cargo tauri build --bundles deb,rpm
            # 容器内原生构建产物直接位于 CARGO_TARGET_DIR/release/bundle(无 triple 子目录)
            find /work/target-linux/release/bundle -maxdepth 2 -type f \( -name "*.deb" -o -name "*.rpm" \) \
                -exec cp -v {} /work/dist/ \;
            chown -R '"$UID_GID"' /work/dist || true
        '
    echo ">>> Linux $ARCH_TAG 安装包已复制到 dist/"
}

# ---------------------------------------------------------------- 入口
WANT="${1:-all}"
[ $# -gt 0 ] && shift

case "$WANT" in
    macos)   build_macos "$@" ;;
    windows) build_windows "$@" ;;
    linux)   build_linux "$@" ;;
    all)
        build_macos "$@" || echo ">>> macOS 本机架构构建失败,已跳过" >&2
        if [ "$(uname)" = "Darwin" ]; then
            build_macos --target x86_64-apple-darwin || echo ">>> macOS x86_64 构建失败,已跳过" >&2
        fi
        build_windows
        build_linux
        build_linux --platform amd64
        ;;
    *)
        echo "用法: $0 [all|macos|windows|linux] [--target <rust-triple>|--platform <amd64|arm64>]" >&2
        exit 1
        ;;
esac

echo ""
echo "=== dist/ 产物清单 ==="
ls -la dist/
