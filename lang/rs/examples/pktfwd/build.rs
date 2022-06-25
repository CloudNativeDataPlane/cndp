/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */
extern crate bindgen;

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    // PKG_CONFIG_PATH environment variable should be set to directory containing libcndp.pc file.
    let pkg_lib_dir = pkg_config::get_variable("libcndp", "libdir").unwrap();
    let pkg_include_dir = pkg_config::get_variable("libcndp", "includedir").unwrap();

    // Tell cargo to tell rustc to link the cndp shared library.
    println!("cargo:rustc-link-search=native={}", pkg_lib_dir);
    println!("cargo:rustc-link-lib=cndp");

    // Tell cargo to invalidate the built crate whenever the wrapper.h or jcfg_parse changes
    println!("cargo:rerun-if-changed=wrapper.h");
    let jcfg_parse_files = fs::read_dir("./jcfg_parse").unwrap();
    for file in jcfg_parse_files {
        println!("cargo:rerun-if-changed={}", file.unwrap().path().display())
    }

    // Build jcfg_parse library.
    let jcfg_parse_build_path = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let jcfg_parse_build_path = jcfg_parse_build_path.join("build");
    let jcfg_parse_build_path = jcfg_parse_build_path.to_str().unwrap();
    meson::build("jcfg_parse", jcfg_parse_build_path);

    // Set jcfg_parse library path.
    println!("cargo:rustc-link-search=native={}", jcfg_parse_build_path);
    println!("cargo:rustc-link-lib=rust_jcfg_parse");

    // Set cndp include search path CNDP_INCLUDE_PATH from environment variable.
    let cndp_include_clang_arg = format!(r#"-I{}/cndp"#, pkg_include_dir);

    // Set LD_LIBRARY_PATH env. This is required to run cargo tests.
    println!(
        "cargo:rustc-env=LD_LIBRARY_PATH={}:{}",
        pkg_lib_dir, jcfg_parse_build_path
    );

    // The bindgen::Builder is the main entry point to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate bindings for.
        .header("wrapper.h")
        .clang_arg(cndp_include_clang_arg)
        // Tell cargo to invalidate the built crate whenever any of the included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $CARGO_MANIFEST_DIR/src/bindings.rs file.
    let mut out_path_manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    out_path_manifest.push("src");
    bindings
        .write_to_file(out_path_manifest.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
