//! The TALs bundled with Routinator.


//------------ BundledTal ----------------------------------------------------

/// Description and content of a TAL bundled with Routinator.
pub struct BundledTal {
    /// The short name of the TAL.
    pub name: &'static str,

    /// A description of the TAL.
    pub description: &'static str,

    /// The category of the TAL.
    pub category: Category,

    /// Does this TAL need explicit opt-in and if so, how is it to be done?
    pub opt_in: Option<OptIn>,

    /// The actual content of the TAL.
    pub content: &'static str,
}


//------------ OptIn ---------------------------------------------------------

/// Information about performing the opt-in procedure for some TALs.
pub struct OptIn {
    /// The command line option for explicitely opting in.
    pub option_name: &'static str,

    /// The help text for the command line option.
    pub option_help: &'static str,

    /// The text to show when opt-in is missing.
    pub message: &'static str,
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
        opt_in: None,
        content: include_str!("../tals/afrinic.tal"),
    },
    BundledTal {
        name: "apnic",
        description: "APNIC production TAL",
        category: Category::Production,
        opt_in: None,
        content: include_str!("../tals/apnic.tal"),
    },
    BundledTal {
        name: "arin",
        description: "ARIN production TAL",
        category: Category::Production,
        opt_in: Some(OptIn {
            option_name: "accept-arin-rpa",
            option_help:
                "You have read and accept \
                 https://www.arin.net/resources/manage/rpki/rpa.pdf",
            message:
                "Before we can install the ARIN TAL, you must have read\n\
                 and agree to the ARIN Relying Party Agreement (RPA).\n\
                 It is available at\n\
                 \n\
                 https://www.arin.net/resources/manage/rpki/rpa.pdf\n\
                 \n\
                 If you agree to the RPA, please run the command\n\
                 again with the --accept-arin-rpa option."
        }),
        content: include_str!("../tals/arin.tal"),
    },
    BundledTal {
        name: "lacnic",
        description: "LACNIC production TAL",
        category: Category::Production,
        opt_in: None,
        content: include_str!("../tals/lacnic.tal"),
    },
    BundledTal {
        name: "ripe",
        description: "RIPE production TAL",
        category: Category::Production,
        opt_in: None,
        content: include_str!("../tals/ripe.tal"),
    },

    // RIR Testbed TALS
    BundledTal {
        name: "apnic-testbed",
        description: "APNIC RPKI Testbed",
        category: Category::RirTest,
        opt_in: None,
        content: include_str!("../tals/apnic-testbed.tal"),
    },
    BundledTal {
        name: "arin-ote",
        description: "ARIN Operational Test and Evaluation Environment",
        category: Category::RirTest,
        opt_in: None,
        content: include_str!("../tals/arin-ote.tal"),
    },
    BundledTal {
        name: "ripe-pilot",
        description: "RIPE NCC RPKI Test Environment",
        category: Category::RirTest,
        opt_in: None,
        content: include_str!("../tals/ripe-pilot.tal"),
    },

    // Other Testbed TALs
    BundledTal {
        name: "nlnetlabs-testbed",
        description: "NLnet Labs RPKI Testbed",
        category: Category::Test,
        opt_in: None,
        content: include_str!("../tals/nlnetlabs-testbed.tal"),
    }
];

