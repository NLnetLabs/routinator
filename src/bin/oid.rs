//! A tool to print the DER encoding of OIDs.

use std::env;
use std::str::FromStr;

fn main() {
    let mut ids = Vec::new();
    let mut octets = Vec::new();
    let mut args = env::args().skip(1);
    ids.push(
        u32::from_str(&args.next().unwrap()).unwrap() * 40 +
        u32::from_str(&args.next().unwrap()).unwrap()
    );
    for id in args {
        ids.push(u32::from_str(&id).unwrap())
    }

    for id in ids {
        if id < 0x80 {
            octets.push(id as u8);
        }
        else if id < 0x4000 {
            octets.push((id >> 7 | 0x80) as u8);
            octets.push((id & 0x7F) as u8);
        }
        else if id < 0x200000 {
            octets.push((id >> 14 | 0x80) as u8);
            octets.push(((id >> 7) & 0x7F | 0x80) as u8);
            octets.push((id & 0x7F) as u8);
        }
        else {
            panic!("Number too big: {}", id)
        }
    }
    println!("{:?}", octets);
    /*
    print!("Hex: [");
    for i in octets { print!("0x{:02x}, ", i); }
    println!("]");
    */
}
