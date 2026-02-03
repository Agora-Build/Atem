fn main() {
    println!("cargo:rerun-if-changed=native/src/atem_rtm.cpp");
    println!("cargo:rerun-if-changed=native/src/atem_rtm_real.cpp");
    println!("cargo:rerun-if-changed=native/include/atem_rtm.h");

    let use_real_rtm = std::env::var("CARGO_FEATURE_REAL_RTM").is_ok();

    let mut build = cc::Build::new();
    build
        .cpp(true)
        .include("native/include")
        .flag_if_supported("-std=c++17")
        .flag_if_supported("-Wall")
        .flag_if_supported("-Wextra")
        .flag_if_supported("-Wpedantic");

    if use_real_rtm {
        build
            .file("native/src/atem_rtm_real.cpp")
            .include("native/third_party/agora/rtm_linux/rtm/sdk/high_level_api/include");
        build.compile("atem_rtm");

        // Link against Agora RTM SDK shared libraries
        let sdk_dir = std::path::PathBuf::from("native/third_party/agora/rtm_linux/rtm/sdk");
        let sdk_abs = std::fs::canonicalize(&sdk_dir)
            .unwrap_or_else(|_| std::path::PathBuf::from(&sdk_dir));
        println!("cargo:rustc-link-search=native={}", sdk_abs.display());
        println!("cargo:rustc-link-lib=dylib=agora_rtm_sdk");
        println!("cargo:rustc-link-lib=dylib=aosl");

        // Set rpath so the binary can locate the SDK .so at runtime
        println!(
            "cargo:rustc-link-arg=-Wl,-rpath,{}",
            sdk_abs.display()
        );
        println!("cargo:rustc-link-arg=-Wl,-rpath,$ORIGIN/../native/third_party/agora/rtm_linux/rtm/sdk");
    } else {
        build.file("native/src/atem_rtm.cpp");
        build.compile("atem_rtm_stub");
    }
}
