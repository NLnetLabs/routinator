//! Integration tests.
#![cfg(test)]

use std::io::Read;
use std::path::Path;
use std::fs;

//------------ read_roas -----------------------------------------------------
//
// Reads all ROAs in the test/repositories directory.

#[test]
fn read_roas() {
    read_dir(&Path::new("test/repositories"));
}

fn read_dir<P: AsRef<Path>>(path: &P) {
    for entry in fs::read_dir(path).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if entry.metadata().unwrap().is_dir() {
            read_dir(&path)
        }
        else if let Some(extension) = path.extension() {
            if extension == "roa" {
                read_roa_file(&path)
            }
        }
    }
}

fn read_roa_file<P: AsRef<Path>>(path: &P) {
    println!("{}", path.as_ref().display());
    let mut file = fs::File::open(path).unwrap();
    let mut data = Vec::new();
    file.read_to_end(&mut data).unwrap();
    let _roa = ::sigobj::SignedObject::parse_slice(&data).unwrap();
}
