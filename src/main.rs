extern crate env_logger;
extern crate rpki;

use std::path::Path;
use rpki::repository::Repository;

fn main() {
    env_logger::init();
    Repository::new(Path::new("test")).process().unwrap();
}
