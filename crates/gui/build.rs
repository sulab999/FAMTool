fn main() {
    // 注意:build.rs 本身按宿主机编译,#[cfg(target_os)] 判断的是宿主而非目标。
    // 交叉编译时必须用 cargo 注入的 CARGO_CFG_TARGET_OS 在运行时判断目标平台。
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo:rerun-if-changed=../../native/audit/main.m");
        println!("cargo:rerun-if-changed=../../native/audit/service_bridge.m");
        println!("cargo:rerun-if-changed=../../native/audit/code_identity.h");
        println!("cargo:rerun-if-changed=../../native/audit/com.famtool.audit.plist");
        cc::Build::new()
            .archiver("/usr/bin/ar")
            .ranlib("/usr/bin/ranlib")
            .file("../../native/audit/service_bridge.m")
            .flag("-fobjc-arc")
            .flag("-fblocks")
            .flag("-mmacosx-version-min=11.0")
            .warnings(true)
            .compile("audit_service_bridge");
        // Rust's -nodefaultlibs omits the Clang availability runtime used by
        // Objective-C @available checks, which release/LTO still needs.
        let runtime = std::process::Command::new("/usr/bin/xcrun")
            .args(["clang", "--print-resource-dir"])
            .output()
            .expect("无法找到 Clang 运行库");
        assert!(runtime.status.success(), "Clang 运行库查询失败");
        let runtime = std::path::PathBuf::from(String::from_utf8(runtime.stdout).unwrap().trim())
            .join("lib/darwin");
        println!("cargo:rustc-link-search=native={}", runtime.display());
        println!("cargo:rustc-link-lib=static=clang_rt.osx");
        for framework in ["Foundation", "AppKit", "Security", "ServiceManagement"] {
            println!("cargo:rustc-link-lib=framework={framework}");
        }
        println!("cargo:rerun-if-changed=../../native/audit/entitlements.plist");
        println!("cargo:rerun-if-changed=../../scripts/build_audit_macos.sh");
        println!("cargo:rerun-if-env-changed=WJ_AUDIT_SIGN_IDENTITY");
        let manifest = std::path::PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
        let temporary = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap())
            .join("famtool-audit");
        let status = std::process::Command::new("bash")
            .arg(manifest.join("../../scripts/build_audit_macos.sh"))
            .arg(&temporary)
            .status()
            .expect("无法运行审计辅助程序构建脚本");
        assert!(status.success(), "审计辅助程序编译失败");
        let resources = manifest.join("resources");
        std::fs::create_dir_all(&resources).unwrap();
        let destination = resources.join("famtool-audit");
        if std::fs::read(&destination).ok() != std::fs::read(&temporary).ok() {
            std::fs::copy(temporary, destination).unwrap();
        }
    }
    tauri_build::build()
}
