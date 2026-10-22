//! `cargo run -p atem-client-ffi --features bindgen --bin uniffi-bindgen --
//! generate --library <libatem_client_ffi.so|.dylib> --language kotlin|swift
//! --out-dir <dir>`
fn main() {
    uniffi::uniffi_bindgen_main()
}
