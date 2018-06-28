extern crate rpki;

use std::path::Path;
use rpki::repository::Repository;

fn main() {
    Repository::new(Path::new("test")).process().unwrap()
}
