fn main() {
    println!("cargo:rerun-if-changed=native/src/atem_rtm.cpp");
    println!("cargo:rerun-if-changed=native/include/atem_rtm.h");

    cc::Build::new()
        .cpp(true)
        .file("native/src/atem_rtm.cpp")
        .include("native/include")
        .flag_if_supported("-std=c++17")
        .flag_if_supported("-Wall")
        .flag_if_supported("-Wextra")
        .flag_if_supported("-Wpedantic")
        .compile("atem_rtm_stub");
}
