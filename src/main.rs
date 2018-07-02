extern crate env_logger;
extern crate log;
extern crate rpki;

use std::path::Path;
use rpki::repository::Repository;

fn main() {
    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Debug)
        .init();

    Repository::new(Path::new("test")).process().unwrap();
}
