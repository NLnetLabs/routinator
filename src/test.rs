//! Integration tests.
#![cfg(test)]

use std::io::Read;
use std::path::Path;
use std::fs;
use bytes::Bytes;

//------------ read_repository -----------------------------------------------
//

#[test]
fn read_repository() {
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
            println!("{}", path.display());
            if extension == "cer" {
                read_cer_file(&path)
            }
            else if extension == "crl" {
                read_crl_file(&path)
            }
            else if extension == "mft" {
                read_mft_file(&path)
            }
            else if extension == "roa" {
                read_roa_file(&path)
            }
            else {
                println!("{}", path.display());
            }
        }
    }
}

fn read_cer_file<P: AsRef<Path>>(path: &P) {
    let mut file = fs::File::open(path).unwrap();
    let mut data = Vec::new();
    file.read_to_end(&mut data).unwrap();
    let _cert = ::cert::Cert::decode(Bytes::from(data)).unwrap();
}

fn read_crl_file<P: AsRef<Path>>(path: &P) {
    let mut file = fs::File::open(path).unwrap();
    let mut data = Vec::new();
    file.read_to_end(&mut data).unwrap();
    let _crl = ::crl::Crl::decode(Bytes::from(data)).unwrap();
}

fn read_mft_file<P: AsRef<Path>>(path: &P) {
    let mut file = fs::File::open(path).unwrap();
    let mut data = Vec::new();
    file.read_to_end(&mut data).unwrap();
    let _mft = ::sigobj::SignedObject::decode(Bytes::from(data)).unwrap();
}

fn read_roa_file<P: AsRef<Path>>(path: &P) {
    let mut file = fs::File::open(path).unwrap();
    let mut data = Vec::new();
    file.read_to_end(&mut data).unwrap();
    let _roa = ::sigobj::SignedObject::decode(Bytes::from(data)).unwrap();
}

