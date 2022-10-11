//! The TALs bundled with Routinator.

use std::collections::HashMap;
use log::error;
use rpki::repository::tal::Tal;
use crate::config::Config;
use crate::error::Failed;


//------------ collect_tals --------------------------------------------------

/// Produces the set of bundled TALs to use from config.
pub fn collect_tals(config: &Config) -> Result<Vec<Tal>, Failed> {
    let mut res = HashMap::new();

    // Add all explicitely mentioned TALs.
    for name in &config.bundled_tals {
        let mut added = false;
        for tal in BUNDLED_TALS {
            if tal.name == name {
                if !res.contains_key(tal.name) {
                    res.insert(tal.name.to_string(), tal.to_tal());
                }
                added = true;
                break;
            }
        }
        if !added {
            error!("Unknown TAL '{}' in --tal option", name);
            return Err(Failed)
        }
    }

    // Add all the RIR TALs unless specifically disabled.
    //
    // (We are doing this second because it cannot ever fail.)
    if !config.no_rir_tals {
        for tal in BUNDLED_TALS {
            if
                tal.category == Category::Production
                && !res.contains_key(tal.name)
            {
                res.insert(tal.name.to_string(), tal.to_tal());

            }
        }
    }

    for tal in res.values_mut() {
        tal.prefer_https()
    }

    Ok(res.into_values().collect())
}


//------------ print_tals ----------------------------------------------------

/// Prints all the bundled TALs to stdout.
pub fn print_tals() {
    let max_len = BUNDLED_TALS.iter().map(|tal| 
        tal.name.len()
    ).max().unwrap_or(0) + 2;

    println!(" .---- --rir-tals");
    println!(" |  .- --rir-test-tals");
    println!(" V  V\n");

    for tal in BUNDLED_TALS {
        match tal.category {
            Category::Production => print!(" X      "),
            Category::RirTest => print!("    X   "),
            _ => print!("        "),
        }
        println!(
            "{:width$} {}", tal.name, tal.description, width = max_len
        );
    }
}


//------------ BundledTal ----------------------------------------------------

/// Description and content of a TAL bundled with Routinator.
pub struct BundledTal {
    /// The short name of the TAL.
    pub name: &'static str,

    /// A description of the TAL.
    pub description: &'static str,

    /// The category of the TAL.
    pub category: Category,

    /// The actual content of the TAL.
    pub content: &'static str,
}

impl BundledTal {
    fn to_tal(&self) -> Tal {
        Tal::read_named(
            self.name.into(), &mut self.content.as_bytes()
        ).expect("bundled broken TAL")
    }
}


//------------ Category ------------------------------------------------------

/// The category of a TAL.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Category {
    /// One of the five RIR TALs.
    Production,

    /// A TAL for a testbed of one of the five RIRs.
    RirTest,

    /// A TAL for a third-party test bed.
    Test,

    /// Any other TAL.
    Other,
}


//------------ All Bundled TALs ----------------------------------------------

/// All TALs bundled with Routinators.
pub static BUNDLED_TALS: &[BundledTal] = &[

    //--- Production RIR TALs.
    //
    BundledTal {
        name: "afrinic",
        description: "AFRINIC production TAL",
        category: Category::Production,
        content: include_str!("../tals/afrinic.tal"),
    },
    BundledTal {
        name: "apnic",
        description: "APNIC production TAL",
        category: Category::Production,
        content: include_str!("../tals/apnic.tal"),
    },
    BundledTal {
        name: "arin",
        description: "ARIN production TAL",
        category: Category::Production,
        content: include_str!("../tals/arin.tal"),
    },
    BundledTal {
        name: "lacnic",
        description: "LACNIC production TAL",
        category: Category::Production,
        content: include_str!("../tals/lacnic.tal"),
    },
    BundledTal {
        name: "ripe",
        description: "RIPE production TAL",
        category: Category::Production,
        content: include_str!("../tals/ripe.tal"),
    },

    // RIR Testbed TALS
    BundledTal {
        name: "apnic-testbed",
        description: "APNIC RPKI Testbed",
        category: Category::RirTest,
        content: include_str!("../tals/apnic-testbed.tal"),
    },
    BundledTal {
        name: "arin-ote",
        description: "ARIN Operational Test and Evaluation Environment",
        category: Category::RirTest,
        content: include_str!("../tals/arin-ote.tal"),
    },
    BundledTal {
        name: "ripe-pilot",
        description: "RIPE NCC RPKI Test Environment",
        category: Category::RirTest,
        content: include_str!("../tals/ripe-pilot.tal"),
    },

    // Other Testbed TALs
    BundledTal {
        name: "nlnetlabs-testbed",
        description: "NLnet Labs RPKI Testbed",
        category: Category::Test,
        content: include_str!("../tals/nlnetlabs-testbed.tal"),
    }
];

