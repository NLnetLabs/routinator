extern crate rustc_version;
use rustc_version::{Version, version};

fn main() {
    #[cfg(feature="static")]
    {
        println!("cargo:rustc-link-lib=static=ssl");
        println!("cargo:rustc-link-lib=static=crypto");
    }
    let version = version().expect("Failed to get rustc version.");
    if version < Version::parse("1.34.0").unwrap() {
        eprintln!(
            "\n\nAt least Rust version 1.34 is required.\n\
             Version {} is used for building.\n\
             Build aborted.\n\n",
             version);
        panic!();
    }
}
