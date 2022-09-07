/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2022 Intel Corporation.
 */

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let cndp_install_path = env::var("CNDP_INSTALL_PATH").ok();
    let default_lib_dir = String::from("/usr/local/lib/x86_64-linux-gnu");
    let default_include_dir = String::from("/usr/local/include");

    // If CNDP_INSTALL_PATH is passed in as a command line argument in cargo build use it
    // to get CNDP library and include path.
    let (cndp_lib_dir, cndp_include_dir) = match cndp_install_path {
        Some(install_path) => (
            install_path.to_string() + &default_lib_dir,
            install_path + &default_include_dir,
        ),
        None => {
            // PKG_CONFIG_PATH environment variable should be set to directory containing libcndp.pc file.
            // If we cannot resolve cndp using pkg-config then use default library/include path.
            let cndp_lib_dir =
                pkg_config::get_variable("libcndp", "libdir").unwrap_or(default_lib_dir);
            let cndp_include_dir =
                pkg_config::get_variable("libcndp", "includedir").unwrap_or(default_include_dir);
            (cndp_lib_dir, cndp_include_dir)
        }
    };

    // Tell cargo to tell rustc to link the cndp shared library.
    println!("cargo:rustc-link-search=native={}", cndp_lib_dir);
    println!("cargo:rustc-link-lib=cndp");

    // Tell cargo to invalidate the built crate whenever the .h or .c or meson.build files in bindings directory changes.
    let bindings_parse_files = fs::read_dir("./src/c_src")
        .expect("Error reading directory")
        .filter_map(Result::ok)
        .filter_map(|f| {
            f.path().extension().and_then(|s| s.to_str()).and_then(|s| {
                if s.eq("h") || s.eq("c") || s.eq("build") {
                    Some(f)
                } else {
                    None
                }
            })
        });

    for file in bindings_parse_files {
        println!("cargo:rerun-if-changed={}", file.path().display());
    }
    // Build rust_bindings library.
    let rust_bindings_build_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    let rust_bindings_build_path = rust_bindings_build_path.to_str().unwrap();
    meson::build("./src/c_src", rust_bindings_build_path);

    // Set rust_bindings library path.
    println!(
        "cargo:rustc-link-search=native={}",
        rust_bindings_build_path
    );
    println!("cargo:rustc-link-lib=cne_rust_bindings");

    // Set cndp include search path CNDP_INCLUDE_PATH from environment variable.
    let cndp_include_clang_arg = format!(r#"-I{}/cndp"#, cndp_include_dir);

    // Set LD_LIBRARY_PATH env. This is required to run cargo tests.
    println!(
        "cargo:rustc-env=LD_LIBRARY_PATH={}:{}",
        cndp_lib_dir, rust_bindings_build_path
    );

    // The bindgen::Builder is the main entry point to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate bindings for.
        .header("src/c_src/wrapper.h")
        .clang_arg(cndp_include_clang_arg)
        // Tell cargo to invalidate the built crate whenever any of the included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .layout_tests(false)
        .derive_default(true)
        .explicit_padding(true)
        .default_enum_style(bindgen::EnumVariation::Consts)
        .prepend_enum_name(false)
        .generate_comments(false)
        .emit_builtins()
        .allowlist_function("cne_.+")
        .allowlist_function("pktdev_.+")
        .allowlist_function("_pktdev_.+")
        .allowlist_function("xskdev_.+")
        .allowlist_function("_xskdev_.+")
        .allowlist_function("pktmbuf_.+")
        .allowlist_function("_pktmbuf_.+")
        .allowlist_function("lport_.+")
        .allowlist_function("mmap_.+")
        .allowlist_function("udsc_.+")
        .allowlist_function("mempool_.+")
        .allowlist_type("cne_.+")
        .allowlist_type("pkt_+")
        .allowlist_type("xsk_+")
        .allowlist_type("lport_.+")
        .allowlist_type("uds_.+")
        .allowlist_type("mempool_.+")
        .allowlist_var("LPORT_.+")
        .allowlist_var("MEMPOOL_.+")
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path_manifest = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path_manifest.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
