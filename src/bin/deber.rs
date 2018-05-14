//! Decodes and prints a BER-encoded file.
extern crate untrusted;
extern crate rpki;

use std::env;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use rpki::ber::{Content, Error, Length, Tag};


fn decode_value(
    indent: usize, tag: Tag, length: Length, content: Option<&mut Content>
) -> Result<(), Error> {
    for _ in 0..indent { print!("  "); }
    print!("{:?} {:?}", tag, length);
    match content {
        None => println!(" primitive"),
        Some(content) => {
            println!(" constructed");
            decode_content(indent + 1, content)?;
        }
    }
    Ok(())
}

fn decode_content(indent: usize, content: &mut Content) -> Result<(), Error> {
    while let Some(()) = content.any(|t, l, c| decode_value(indent, t, l, c))? {
    }
    Ok(())
}

fn print_file<P: AsRef<Path>>(path: &P) {
    let mut file = File::open(path).unwrap();
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).unwrap();
    Content::parse_slice(&buf, |content| {
        decode_content(0, content)
    }).unwrap();
}

fn main() {
    for path in env::args().skip(1) {
        print_file(&path);
    }
}
