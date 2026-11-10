fn main() {
    let config = slint_build::CompilerConfiguration::new().with_style("fluent".into());
    slint_build::compile_with_config("ui/app.slint", config).expect("compile ui/app.slint");

    // Icons, version info and the application manifest.
    println!("cargo:rerun-if-changed=app.rc");
    println!("cargo:rerun-if-changed=app.manifest");
    println!("cargo:rerun-if-changed=assets");
    embed_resource::compile("app.rc", embed_resource::NONE)
        .manifest_optional()
        .expect("compile app.rc");

    // WinFsp's DLL is loaded at runtime from its install folder (not on PATH).
    println!("cargo:rustc-link-lib=dylib=delayimp");
    println!("cargo:rustc-link-arg=/DELAYLOAD:winfsp-x64.dll");
    println!("cargo:rustc-link-arg=/IGNORE:4199");
}
