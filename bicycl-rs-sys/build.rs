use std::env;
use std::path::PathBuf;
use std::process::Command;

fn env_or(var: &str, default: &str) -> String {
    env::var(var).unwrap_or_else(|_| default.to_string())
}

fn emit_link_lib(kind: &str, name: &str) {
    if !name.is_empty() {
        println!("cargo:rustc-link-lib={kind}={name}");
    }
}

fn emit_cpp_runtime_link() {
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    let (default_kind, default_name) = match (target_os.as_str(), target_env.as_str()) {
        ("macos", _) => ("dylib", "c++"),
        ("windows", "msvc") => ("", ""),
        ("windows", "gnu") => ("dylib", "stdc++"),
        ("windows", _) => ("", ""),
        _ => ("dylib", "stdc++"),
    };
    let kind =
        env::var("BICYCL_CPP_RUNTIME_LINK_KIND").unwrap_or_else(|_| default_kind.to_string());
    let name = env::var("BICYCL_CPP_RUNTIME_LIB_NAME").unwrap_or_else(|_| default_name.to_string());
    if !kind.is_empty() && !name.is_empty() {
        emit_link_lib(&kind, &name);
    }
}

fn emit_third_party_links() {
    emit_link_lib(
        &env_or("BICYCL_GMPXX_LINK_KIND", "dylib"),
        &env_or("BICYCL_GMPXX_LIB_NAME", "gmpxx"),
    );
    emit_link_lib(
        &env_or("BICYCL_GMP_LINK_KIND", "dylib"),
        &env_or("BICYCL_GMP_LIB_NAME", "gmp"),
    );
    emit_link_lib(
        &env_or("BICYCL_CRYPTO_LINK_KIND", "dylib"),
        &env_or("BICYCL_CRYPTO_LIB_NAME", "crypto"),
    );
}

fn has_cmake() -> bool {
    Command::new("cmake")
        .arg("--version")
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn main() {
    println!("cargo:rerun-if-env-changed=DOCS_RS");
    if env::var_os("DOCS_RS").is_some() || env::var_os("CARGO_FEATURE_DOCSRS").is_some() {
        return;
    }

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let capi_dir = manifest_dir.join("capi");
    let bicycl_source_dir = env::var("BICYCL_SOURCE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| manifest_dir.join("vendor").join("bicycl"));

    if !has_cmake() {
        panic!("CMake was not found in PATH. Install CMake to build.");
    }

    let mut cfg = cmake::Config::new(capi_dir);
    cfg.profile("Release");
    cfg.define("BICYCL_SOURCE_DIR", &bicycl_source_dir);
    let dst = cfg.build();

    let lib_dir = dst.join("lib");
    let fallback_lib_dir = dst.join("build");

    if lib_dir.exists() {
        println!("cargo:rustc-link-search=native={}", lib_dir.display());
    } else {
        println!(
            "cargo:rustc-link-search=native={}",
            fallback_lib_dir.display()
        );
    }

    println!("cargo:rustc-link-lib=static=bicycl_capi");
    emit_cpp_runtime_link();
    emit_third_party_links();
    println!("cargo:rerun-if-changed=capi/include/bicycl_capi.h");
    println!("cargo:rerun-if-changed=capi/src/bicycl_capi.cpp");
    println!("cargo:rerun-if-changed=capi/CMakeLists.txt");
    println!("cargo:rerun-if-changed=vendor/bicycl/src");
    println!("cargo:rerun-if-env-changed=BICYCL_SOURCE_DIR");
}
