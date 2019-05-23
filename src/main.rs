#[macro_use] extern crate clap;
#[macro_use] extern crate log;
extern crate routinator;

use std::env::current_dir;
use std::process::exit;
use clap::App;
use routinator::{Config, Error, Operation};

// Since `main` with a result currently insists on printing a message, but
// in our case we only get an `Error` if all is said and done, we make our
// own, more quiet version.
fn _main() -> Result<(), Error> {
    Operation::init()?;
    let cur_dir = match current_dir() {
        Ok(dir) => dir,
        Err(err) => {
            error!(
                "Fatal: cannot get current directory ({}). Aborting.",
                err
            );
            return Err(Error);
        }
    };
    let matches = Operation::config_args(Config::config_args(
        App::new("Routinator")
            .version(crate_version!())
            .author(crate_authors!())
            .about("collects and processes RPKI repository data")
    )).get_matches();
    let mut config = Config::from_arg_matches(&matches, &cur_dir)?;
    let operation = Operation::from_arg_matches(
        &matches, &cur_dir, &mut config
    )?;
    operation.run(config)
}

fn main() {
    match _main() {
        Ok(_) => exit(0),
        Err(_) => exit(1),
    }
}

