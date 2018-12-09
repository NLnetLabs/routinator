#[macro_use] extern crate clap;
extern crate routinator;

use std::process::exit;
use clap::App;
use routinator::operation::{Error, Orders};

// Since `main` with a result currently insists on printing a message, we
// make our own, more quiet version of it.
fn _main() -> Result<(), Error> {
    Orders::from_args(
        App::new("Routinator")
            .version(crate_version!())
            .author(crate_authors!())
            .about("collects and processes RPKI repository data")
    )?.run()
}

fn main() {
    match _main() {
        Ok(_) => exit(0),
        Err(_) => exit(1),
    }
}

