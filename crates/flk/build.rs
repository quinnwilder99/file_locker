fn main() {
    // `flk mount` loads WinFsp's DLL at runtime from its install folder
    // (it is not on PATH), so link it delay-loaded.
    winfsp::build::winfsp_link_delayload();
    // Test harnesses that never call WinFsp make the linker warn that the
    // delay-load is unused (LNK4199); that is expected.
    println!("cargo:rustc-link-arg=/IGNORE:4199");
}
