extern crate env_logger;
extern crate log;
extern crate rpki;

use std::path::Path;
use rpki::repository::Repository;

fn main() {
    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Debug)
        .init();

    let repo = Repository::new(Path::new("test"));
    if let Err(_) = repo.update() {
        println!("Update failed. Continuing anyway.");
    }
    let roas = match repo.process() {
        Ok(res) => res,
        Err(_) => {
            println!("Fatal error during validation. Aborted.");
            ::std::process::exit(1);
        }
    };

    println!("ASN,IP Prefix,Max Length");
    for roa in roas.drain() {
        for addr in roa.v4_addrs().iter() {
            let addr = addr.as_v4();
            println!("{},{}/{},{}",
                roa.as_id(),
                addr.address(), addr.address_length(),
                addr.max_length()
            );
        }
        for addr in roa.v6_addrs().iter() {
            let addr = addr.as_v6();
            println!("{},{}/{},{}",
                roa.as_id(),
                addr.address(), addr.address_length(),
                addr.max_length()
            );
        }
    }
}
