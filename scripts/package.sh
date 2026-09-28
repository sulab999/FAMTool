#!/usr/bin/env bash
# FAMTool 全平台打包脚本 —— 一键生成 dist/ 下的安装程序:
#   macOS  : FAMTool_*_macos_{aarch64,x86_64}.dmg
#   Windows: FAMTool_*_x64-setup.exe            (NSIS,macOS/Linux 上经 cargo-xwin 交叉构建)
#   Linux  : FAMTool_*.deb / FAMTool-*.rpm      (Docker 容器内构建,双架构)
#
# audit-pipe 是 Tauri externalBin(sidecar),每个目标三元组都必须先构建到
# crates/gui/binaries/audit-pipe-<triple>,否则 tauri build 直接失败;
# 本脚本在每个平台构建前自动完成这一步。
#
# 用法:
#   ./scripts/package.sh                       # 全部平台(缺依赖的平台跳过并提示)
#   ./scripts/package.sh macos                 # 仅 macOS(本机+交叉双架构)
#   ./scripts/package.sh macos --target x86_64-apple-darwin   # 仅指定架构
#   ./scripts/package.sh windows               # 仅 Windows NSIS
#   ./scripts/package.sh linux                 # Linux deb+rpm(本机 Docker 架构)
#   ./scripts/package.sh linux --platform amd64               # 指定 Linux 架构
#   ./scripts/package.sh clean                 # 清理 dist/ 与打包中间产物
#   ./scripts/package.sh --help
#
# 环境变量:
#   WJ_APP_SIGN_IDENTITY    macOS 开发者签名身份(默认 ad-hoc 签名)
#   WJ_AUDIT_SIGN_IDENTITY  审计辅助程序独立签名身份(默认跟随前者)
#   WJ_CARGO_JOBS           Linux 容器内编译并行度(默认 2,防 VM 内存不足)
#   WJ_CLEAN=1              清空 Linux 容器内编译缓存后重编
#   WJ_SKIP_CHECKS=1        跳过打包前的前端测试
set -Eeuo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
mkdir -p dist

# ---------------------------------------------------------------- 输出与错误
log()  { printf '>>> %s\n' "$*"; }
warn() { printf '>>> [跳过] %s\n' "$*" >&2; }
die()  { printf '!!! %s\n' "$*" >&2; exit 1; }
trap 'printf "!!! 命令失败于 %s 第 %d 行附近(上方日志可见具体步骤)\n" "$BASH_SOURCE" "$LINENO" >&2' ERR

ensure_node() {
    command -v node >/dev/null 2>&1 || die "未找到 Node.js,请先安装"
    if [ ! -d node_modules/@tauri-apps/cli ]; then
        npm ci
    fi
}

preflight() {
    ensure_node
    if [ "${WJ_SKIP_CHECKS:-0}" != "1" ]; then
        log "打包前自检:前端测试(npm test,WJ_SKIP_CHECKS=1 可跳过)"
        npm test --silent
    fi
}

conf_version() {
    python3 -c 'import json;print(json.load(open("crates/gui/tauri.conf.json"))["version"])' 2>/dev/null || echo "unknown"
}

# 构建审计辅助程序 sidecar 到 crates/gui/binaries/audit-pipe-<triple>。
# 三元组含 windows 时产物带 .exe 后缀(由目标决定,与宿主平台无关)。
build_sidecar() {
    local triple="$1" built_dir="$2" bin
    case "$triple" in
        *windows*) bin="$built_dir/audit-pipe.exe" ;;
        *)         bin="$built_dir/audit-pipe" ;;
    esac
    [ -f "$bin" ] || die "sidecar 产物不存在: $bin(编译是否成功?)"
    mkdir -p crates/gui/binaries
    cp "$bin" "crates/gui/binaries/audit-pipe-$triple"
    chmod 755 "crates/gui/binaries/audit-pipe-$triple"
}

# ---------------------------------------------------------------- macOS
build_macos() {
    if [ "$(uname)" != "Darwin" ]; then
        warn "macOS:只能在 macOS 上构建"
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

    if [ -n "${WJ_APP_SIGN_IDENTITY:-}" ]; then
        export APPLE_SIGNING_IDENTITY="$WJ_APP_SIGN_IDENTITY"
        export WJ_AUDIT_SIGN_IDENTITY="${WJ_AUDIT_SIGN_IDENTITY:-$WJ_APP_SIGN_IDENTITY}"
    fi
    # 自定义更新服务器地址(通过 --config 覆盖内置占位地址)
    local CONFIG_ARGS=()
    if [ -n "${WJ_UPDATE_ENDPOINT:-}" ]; then
        # 本地/局域网 http 联调需显式放行非加密传输;正式发布应使用 https
        case "$WJ_UPDATE_ENDPOINT" in
            http://*) printf '{"plugins":{"updater":{"endpoints":["%s"],"dangerousInsecureTransportProtocol":true}}}' "$WJ_UPDATE_ENDPOINT" ;;
            *)        printf '{"plugins":{"updater":{"endpoints":["%s"]}}}' "$WJ_UPDATE_ENDPOINT" ;;
        esac > "$ROOT/target/update-endpoint.json"
        CONFIG_ARGS=(--config "$ROOT/target/update-endpoint.json")
    fi
    # 审计辅助程序 sidecar(tauri externalBin:binaries/audit-pipe-<triple>)
    cargo build -p famtool-cli --bin audit-pipe --release ${TARGET_ARGS[@]+"${TARGET_ARGS[@]}"}
    local TRIPLE
    TRIPLE="${TARGET:-$(rustc -vV | sed -n 's/^host: //p')}"
    build_sidecar "$TRIPLE" "$ARCH_DIR"
    npm run build -- ${TARGET_ARGS[@]+"${TARGET_ARGS[@]}"} ${CONFIG_ARGS[@]+"${CONFIG_ARGS[@]}"} --bundles app


    # tauri 已把 sidecar 打进应用包,这里只做组装与签名
    local SOURCE="$ROOT/$ARCH_DIR/bundle/macos/FAMTool.app"
    [ -d "$SOURCE" ] || die "未找到 Tauri 应用包: $SOURCE"

    local APP_OUT="$ROOT/FAMTool.app"
    local HOST_ARCH
    HOST_ARCH="$(uname -m | sed 's/arm64/aarch64/')"
    if [ -n "$TARGET" ] && [ "$ARCH_TAG" != "$HOST_ARCH" ]; then
        # 交叉架构产物只进 dist/,不覆盖根目录的本机应用包
        APP_OUT="$ROOT/dist/FAMTool.app.$ARCH_TAG"
        rm -rf "$APP_OUT"
    fi
    ditto "$SOURCE" "$APP_OUT"
    if [ -n "${WJ_APP_SIGN_IDENTITY:-}" ]; then
        # Keep the helper's restricted entitlement; sign the containing app last.
        codesign --force --options runtime --sign "$WJ_APP_SIGN_IDENTITY" "$APP_OUT"
    else
        codesign --force --deep --sign - "$APP_OUT"
    fi
    codesign --verify --deep --strict "$APP_OUT"

    # DMG 安装镜像(含应用与 /Applications 快捷方式)
    local VERSION STAGING DMG
    VERSION="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$APP_OUT/Contents/Info.plist" 2>/dev/null || conf_version)"
    DMG="$ROOT/dist/FAMTool_${VERSION}_macos_${ARCH_TAG}.dmg"
    STAGING="$(mktemp -d)"
    ditto "$APP_OUT" "$STAGING/FAMTool.app"
    ln -sf /Applications "$STAGING/Applications"
    hdiutil create -volname FAMTool -srcfolder "$STAGING" -ov -format UDZO -fs HFS+ "$DMG" >/dev/null
    rm -rf "$STAGING"
    [ -s "$DMG" ] || die "DMG 生成失败或为空: $DMG"
    hdiutil verify "$DMG" >/dev/null
    log "已生成并校验 $DMG"
}

# ---------------------------------------------------------------- Windows
build_windows() {
    if ! command -v makensis >/dev/null 2>&1; then
        warn "Windows:未找到 NSIS(makensis)。macOS/Linux 上执行 brew install nsis llvm 并 cargo install cargo-xwin;Windows 上 choco install nsis"
        return 0
    fi
    # Windows 宿主用本机 MSVC 工具链;macOS/Linux 宿主经 cargo-xwin 交叉构建
    local NATIVE=0
    case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*|Windows_NT) NATIVE=1 ;; esac

    local SIDE_CARGO=(build) RUNNER=() TARGET_ARGS=(--target x86_64-pc-windows-msvc)
    if [ "$NATIVE" = "1" ]; then
        log "Windows 宿主:使用本机 MSVC 工具链"
    else
        command -v cargo-xwin >/dev/null 2>&1 || { warn "Windows:未找到 cargo-xwin(cargo install cargo-xwin)"; return 0; }
        if command -v brew >/dev/null 2>&1; then
            local LLVM_BIN
            LLVM_BIN="$(brew --prefix llvm 2>/dev/null || true)/bin"
            if [ -n "${LLVM_BIN%/bin}" ] && [ -d "$LLVM_BIN" ]; then
                export PATH="$LLVM_BIN:$PATH"
            fi
        fi
        # tauri CLI 认 --runner cargo-xwin;直接调 cargo 时对应的是 xwin 子命令
        SIDE_CARGO=(xwin build)
        RUNNER=(--runner cargo-xwin)
    fi

    # 先清空打包输出目录,避免上次构建的旧文件混入 dist
    rm -rf target/x86_64-pc-windows-msvc/release/bundle/nsis
    # 审计辅助程序 sidecar(externalBin 按三元组名收取)
    cargo ${SIDE_CARGO[@]+"${SIDE_CARGO[@]}"} -p famtool-cli --bin audit-pipe --release ${TARGET_ARGS[@]+"${TARGET_ARGS[@]}"}
    build_sidecar x86_64-pc-windows-msvc target/x86_64-pc-windows-msvc/release
    npm run build -- ${RUNNER[@]+"${RUNNER[@]}"} ${TARGET_ARGS[@]+"${TARGET_ARGS[@]}"} --bundles nsis
    find target/x86_64-pc-windows-msvc/release/bundle/nsis -name "*_x64-setup.exe" \
        -exec cp -v {} dist/ \;
    [ -n "$(find dist -maxdepth 1 -name 'FAMTool_*_x64-setup.exe' -print -quit)" ] \
        || die "Windows NSIS 安装程序未生成"

    log "Windows NSIS 安装程序已复制到 dist/"
}

# ---------------------------------------------------------------- Linux
ensure_docker() {
    if docker info >/dev/null 2>&1; then
        return 0
    fi
    # macOS 上尝试自动拉起 Docker Desktop
    if [ "$(uname)" = "Darwin" ] && [ -d "/Applications/Docker.app" ]; then
        log "Docker 未运行,正在启动 Docker Desktop..."
        open -a Docker
        local i
        for i in $(seq 1 30); do
            docker info >/dev/null 2>&1 && { log "Docker 已就绪"; return 0; }
            sleep 3
        done
    fi
    return 1
}

build_linux() {
    ensure_docker || { warn "Linux:需要运行中的 Docker(Docker Desktop)"; return 0; }
    local PLATFORM="linux/arm64" ARCH_TAG="aarch64"
    if [ "${1:-}" = "--platform" ]; then
        case "$2" in
            amd64) PLATFORM="linux/amd64"; ARCH_TAG="x86_64" ;;
            arm64) PLATFORM="linux/arm64"; ARCH_TAG="aarch64" ;;
            *) die "不支持的 Linux 架构: $2" ;;
        esac
        shift 2
    fi

    local IMAGE_TAG="famtool-linux-builder:${ARCH_TAG}"
    if ! docker image inspect "$IMAGE_TAG" >/dev/null 2>&1; then
        log "构建 Docker 镜像 $IMAGE_TAG (首次较慢)..."
        if [ "$ARCH_TAG" = "x86_64" ]; then
            docker buildx build --platform "$PLATFORM" -f scripts/docker/Dockerfile.linux -t "$IMAGE_TAG" --load .
        else
            docker build -f scripts/docker/Dockerfile.linux -t "$IMAGE_TAG" .
        fi
    fi

    local UID_GID TRIPLE
    UID_GID="$(id -u):$(id -g)"
    TRIPLE="${ARCH_TAG}-unknown-linux-gnu"
    log "在容器内构建 Linux $ARCH_TAG 安装包 (deb,rpm)..."
    # 注意:不能放在 $() 里调用,那会在子 shell 中 export,密钥传不进 docker
    docker run --rm --platform "$PLATFORM" \
        -v "$ROOT":/work -w /work \
        -e CARGO_TARGET_DIR=/work/target-linux \
        -e CARGO_HOME=/usr/local/cargo \
        -e WJ_CLEAN="${WJ_CLEAN:-0}" \
        -e WJ_CARGO_JOBS="${WJ_CARGO_JOBS:-2}" \
        -e WJ_TRIPLE="$TRIPLE" \
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
            # 审计辅助程序 sidecar(externalBin 按三元组名收取)
            cargo build -p famtool-cli --bin audit-pipe --release
            build_sidecar() {
                mkdir -p /work/crates/gui/binaries
                cp "/work/target-linux/release/audit-pipe" "/work/crates/gui/binaries/audit-pipe-$1"
                chmod 755 "/work/crates/gui/binaries/audit-pipe-$1"
                # 容器内生成的文件属 root,归还宿主用户以免阻塞后续本机构建
                chown -R '"$UID_GID"' /work/crates/gui/binaries || true
            }
            build_sidecar "$WJ_TRIPLE"
            cargo tauri build --bundles deb,rpm
            # 容器内原生构建产物直接位于 CARGO_TARGET_DIR/release/bundle(无 triple 子目录)
            find /work/target-linux/release/bundle -maxdepth 2 -type f \( -name "*.deb" -o -name "*.rpm" \) \
                -exec cp -v {} /work/dist/ \;
            chown -R '"$UID_GID"' /work/dist || true
        '
    # 校验产物确实落盘(容器内 cp 静默失败会让 dist 缺文件)
    # deb 命名形如 FAMTool_1.0.0_arm64.deb;rpm 命名形如 FAMTool-1.0.0-1.aarch64.rpm
    local deb_glob rpm_glob
    if [ "$ARCH_TAG" = "x86_64" ]; then
        deb_glob="dist/FAMTool_*_amd64.deb"; rpm_glob="dist/FAMTool-*x86_64.rpm"
    else
        deb_glob="dist/FAMTool_*_arm64.deb"; rpm_glob="dist/FAMTool-*aarch64.rpm"
    fi
    compgen -G "$deb_glob" >/dev/null || die "Linux $ARCH_TAG:dist/ 中未找到 deb($deb_glob)"
    compgen -G "$rpm_glob" >/dev/null || die "Linux $ARCH_TAG:dist/ 中未找到 rpm($rpm_glob)"

    log "Linux $ARCH_TAG 安装包已就绪"
}

# ---------------------------------------------------------------- 其他动作
gen_checksums() {
    local files
    files="$(find dist -maxdepth 1 -type f -name 'FAMTool*' | LC_ALL=C sort)"
    [ -n "$files" ] || return 0
    printf '%s\n' "$files" | xargs shasum -a 256 > dist/SHA256SUMS
    log "已生成 dist/SHA256SUMS"
}

do_clean() {
    log "清理打包产物与中间文件..."
    rm -rf dist
    rm -rf crates/gui/binaries
    rm -rf target/release/bundle target/aarch64-apple-darwin/release/bundle \
        target/x86_64-apple-darwin/release/bundle target/x86_64-pc-windows-msvc/release/bundle
    if docker info >/dev/null 2>&1; then
        docker volume rm -f famtool-target-linux-aarch64 famtool-target-linux-x86_64 2>/dev/null || true
    fi
    log "清理完成"
}

show_help() {
    awk 'NR>1 && /^#/{sub(/^# ?/,"");print;next} NR>1{exit}' "$BASH_SOURCE"
}

# ---------------------------------------------------------------- 入口
WANT="${1:-all}"
[ $# -gt 0 ] && shift

case "$WANT" in
    -h|--help|help) show_help; exit 0 ;;
    clean)          do_clean; exit 0 ;;
    macos|windows|linux|all) preflight ;;
    *) die "未知目标: $WANT(用法: $0 [all|macos|windows|linux|clean|--help])" ;;
esac

case "$WANT" in
    macos)   build_macos "$@" ;;
    windows) build_windows "$@" ;;
    linux)   build_linux "$@" ;;
    all)
        build_macos "$@" || warn "macOS 本机架构构建失败"
        if [ "$(uname)" = "Darwin" ]; then
            build_macos --target x86_64-apple-darwin || warn "macOS x86_64 构建失败"
        fi
        build_windows
        build_linux
        build_linux --platform amd64
        ;;
esac

gen_checksums

echo ""
echo "=== dist/ 产物清单(版本 $(conf_version)) ==="
ls -la dist/
if compgen -G "dist/FAMTool*" >/dev/null; then
    echo ""
    echo "=== 发布到 GitHub(一键复制) ==="
    # shellcheck disable=SC2046
    echo "gh release create v$(conf_version) $(ls dist/*.dmg dist/*.exe dist/*.deb dist/*.rpm 2>/dev/null | tr '\n' ' ')-t v$(conf_version) -n 'FAMTool $(conf_version)'"
fi
