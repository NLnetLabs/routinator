//! Output of lists of VRPs.

use std::io;
use chrono::Utc;
use chrono::format::{Item, Numeric, Pad};
use rpki::resources::AsId;
use crate::origins::{AddressOrigin, AddressOrigins, AddressPrefix};


//------------ OutputFormat --------------------------------------------------

/// The output format for VRPs.
#[derive(Clone, Copy, Debug)]
pub enum OutputFormat {
    /// CSV format.
    ///
    /// Each row has the AS number, prefix, max-length, and TA.
    Csv,

    /// Extended CSV format.
    ///
    /// Each row has URI, ASN, prefix, max-length, not before, not after.
    ExtendedCsv,

    /// RIPE NCC Validator JSON format.
    ///
    /// This is a JSON object with one element `"roas"` which is an array
    /// of objects, each with the elements `"asn"`, `"prefix"`, `"maxLength"`,
    /// and `"ta"`.
    Json,

    /// OpenBGPD configuration format.
    ///
    /// Specifically, this produces as `roa-set`.
    Openbgpd,

    /// RPSL output.
    ///
    /// This produces a sequence of RPSL objects with various fields.
    Rpsl,

    /// No output.
    ///
    /// Seriously: no output.
    None,
}

impl OutputFormat {
    /// Returns whether this output format requires extra output.
    pub fn extra_output(self) -> bool {
        match self {
            OutputFormat::ExtendedCsv => true,
            _ => false
        }
    }

    /// Outputs `vrps` to `target` in this format.
    ///
    /// This method loggs error messages.
    pub fn output<W: io::Write>(
        self,
        vrps: &AddressOrigins,
        filters: Option<&[Filter]>,
        target: &mut W,
    ) -> Result<(), io::Error> {
        match self._output(vrps, filters, target) {
            Ok(()) => Ok(()),
            Err(ref err) if err.kind() == io::ErrorKind::BrokenPipe => Ok(()),
            Err(err) => Err(err)
        }
    }

    fn _output<W: io::Write>(
        self,
        vrps: &AddressOrigins,
        filters: Option<&[Filter]>,
        target: &mut W,
    ) -> Result<(), io::Error> {
        self.output_header(vrps, target)?;
        let mut first = true;
        for vrp in vrps.iter() {
            if self.output_origin(vrp, filters, first, target)? {
                first = false;
            }
        }
        self.output_footer(vrps, target)
    }

    pub fn output_header<W: io::Write>(
        self,
        vrps: &AddressOrigins,
        target: &mut W
    ) -> Result<(), io::Error> {
        match self {
            OutputFormat::Csv => csv_header(vrps, target),
            OutputFormat::ExtendedCsv => ext_csv_header(vrps, target),
            OutputFormat::Json => json_header(vrps, target),
            OutputFormat::Openbgpd => openbgpd_header(vrps, target),
            OutputFormat::Rpsl => rpsl_header(vrps, target),
            OutputFormat::None => Ok(())
        }
    }

    pub fn output_origin<W: io::Write>(
        self,
        vrp: &AddressOrigin,
        filters: Option<&[Filter]>,
        first: bool,
        target: &mut W
    ) -> Result<bool, io::Error> {
        if Self::skip_origin(vrp, filters) {
            return Ok(false)
        }
        match self {
            OutputFormat::Csv => csv_origin(vrp, first, target)?,
            OutputFormat::ExtendedCsv => ext_csv_origin(vrp, first, target)?,
            OutputFormat::Json => json_origin(vrp, first, target)?,
            OutputFormat::Openbgpd => openbgpd_origin(vrp, first, target)?,
            OutputFormat::Rpsl => rpsl_origin(vrp, first, target)?,
            OutputFormat::None => { }
        }
        Ok(true)
    }

    fn skip_origin(
        origin: &AddressOrigin,
        filters: Option<&[Filter]>
    ) -> bool {
        match filters {
            Some(filters) => {
                for filter in filters {
                    if filter.covers(origin) {
                        return false
                    }
                }
                true
            }
            None => false
        }
    }

    pub fn output_footer<W: io::Write>(
        self,
        vrps: &AddressOrigins,
        target: &mut W
    ) -> Result<(), io::Error> {
        match self {
            OutputFormat::Csv => csv_footer(vrps, target),
            OutputFormat::ExtendedCsv => ext_csv_footer(vrps, target),
            OutputFormat::Json => json_footer(vrps, target),
            OutputFormat::Openbgpd => openbgpd_footer(vrps, target),
            OutputFormat::Rpsl => rpsl_footer(vrps, target),
            OutputFormat::None => Ok(())
        }
    }

    pub fn content_type(self) -> &'static str {
        match self {
            OutputFormat::Csv | OutputFormat::ExtendedCsv
                => "text/csv;charset=utf-8;header=present",
            OutputFormat::Json => "application/json",
            _ => "text/plain;charset=utf-8",
        }
    }
}


//------------ csv -----------------------------------------------------------

fn csv_header<W: io::Write>(
    _vrps: &AddressOrigins,
    output: &mut W,
) -> Result<(), io::Error> {
    writeln!(output, "ASN,IP Prefix,Max Length,Trust Anchor")
}

fn csv_origin<W: io::Write>(
    addr: &AddressOrigin,
    _first: bool,
    output: &mut W,
) -> Result<(), io::Error> {
    writeln!(output, "{},{}/{},{},{}",
        addr.as_id(),
        addr.address(), addr.address_length(),
        addr.max_length(),
        addr.tal_name(),
    )
}

fn csv_footer<W: io::Write>(
    _vrps: &AddressOrigins,
    _output: &mut W,
) -> Result<(), io::Error> {
    Ok(())
}


//------------ ext_csv -------------------------------------------------------

// 2017-08-25 13:12:19
const TIME_ITEMS: &[Item<'static>] = &[
    Item::Numeric(Numeric::Year, Pad::Zero),
    Item::Literal("-"),
    Item::Numeric(Numeric::Month, Pad::Zero),
    Item::Literal("-"),
    Item::Numeric(Numeric::Day, Pad::Zero),
    Item::Literal(" "),
    Item::Numeric(Numeric::Hour, Pad::Zero),
    Item::Literal(":"),
    Item::Numeric(Numeric::Minute, Pad::Zero),
    Item::Literal(":"),
    Item::Numeric(Numeric::Second, Pad::Zero),
];

fn ext_csv_header<W: io::Write>(
    _vrps: &AddressOrigins,
    output: &mut W,
) -> Result<(), io::Error> {
    writeln!(output, "URI,ASN,IP Prefix,Max Length,Not Before,Not After")
}

fn ext_csv_origin<W: io::Write>(
    addr: &AddressOrigin,
    _first: bool,
    output: &mut W,
) -> Result<(), io::Error> {
    match addr.cert() {
        Some(cert) => {
            match cert.signed_object() {
                Some(uri) => {
                    write!(output, "{}", uri)?;
                }
                None => write!(output, "N/A")?
            }
            let val = cert.validity();
            writeln!(output, ",{},{}/{},{},{},{}",
                addr.as_id(),
                addr.address(), addr.address_length(),
                addr.max_length(),
                val.not_before().format_with_items(
                    TIME_ITEMS.iter().cloned()
                ),
                val.not_after().format_with_items(
                    TIME_ITEMS.iter().cloned()
                ),
            )
        }
        None => {
            writeln!(output, "N/A,{},{}/{},{},N/A,N/A",
                addr.as_id(),
                addr.address(), addr.address_length(),
                addr.max_length(),
            )
        }
    }
}

fn ext_csv_footer<W: io::Write>(
    _vrps: &AddressOrigins,
    _output: &mut W,
) -> Result<(), io::Error> {
    Ok(())
}


//------------ json ----------------------------------------------------------

fn json_header<W: io::Write>(
    _vrps: &AddressOrigins,
    output: &mut W,
) -> Result<(), io::Error> {
    writeln!(output, "{{\n  \"roas\": [")
}

fn json_origin<W: io::Write>(
    addr: &AddressOrigin,
    first: bool,
    output: &mut W,
) -> Result<(), io::Error> {
    if !first {
        writeln!(output, ",")?;
    }
    write!(output,
        "    {{ \"asn\": \"{}\", \"prefix\": \"{}/{}\", \
        \"maxLength\": {}, \"ta\": \"{}\" }}",
        addr.as_id(),
        addr.address(), addr.address_length(),
        addr.max_length(),
        addr.tal_name(),
    )
}

fn json_footer<W: io::Write>(
    _vrps: &AddressOrigins,
    output: &mut W,
) -> Result<(), io::Error> {
    writeln!(output, "\n  ]\n}}")
}


//------------ openbgpd ------------------------------------------------------

fn openbgpd_header<W: io::Write>(
    _vrps: &AddressOrigins,
    output: &mut W,
) -> Result<(), io::Error> {
    writeln!(output, "roa-set {{")
}

fn openbgpd_origin<W: io::Write>(
    addr: &AddressOrigin,
    _first: bool,
    output: &mut W,
) -> Result<(), io::Error> {
    write!(output, "    {}/{}", addr.address(), addr.address_length())?;
    if addr.address_length() < addr.max_length() {
        write!(output, " maxlen {}", addr.max_length())?;
    }
    writeln!(output, " source-as {}", u32::from(addr.as_id()))
}

fn openbgpd_footer<W: io::Write>(
    _vrps: &AddressOrigins,
    output: &mut W,
) -> Result<(), io::Error> {
    writeln!(output, "}}")
}


//------------ rpsl ----------------------------------------------------------

fn rpsl_header<W: io::Write>(
    _vrps: &AddressOrigins,
    _output: &mut W,
) -> Result<(), io::Error> {
    Ok(())
}

fn rpsl_origin<W: io::Write>(
    addr: &AddressOrigin,
    _first: bool,
    output: &mut W,
) -> Result<(), io::Error> {
    let now = Utc::now().to_rfc3339();
    writeln!(output,
        "\n{}: {}/{}\norigin: {}\n\
        descr: RPKI attestation\nmnt-by: NA\ncreated: {}\n\
        last-modified: {}\nsource: ROA-{}-RPKI-ROOT\n",
        if addr.address().is_ipv4() { "route" }
        else { "route6" },
        addr.address(), addr.address_length(),
        addr.as_id(), now, now, addr.tal_name().to_uppercase()
    )
}

fn rpsl_footer<W: io::Write>(
    _vrps: &AddressOrigins,
    _output: &mut W,
) -> Result<(), io::Error> {
    Ok(())
}


//------------ Filter --------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub enum Filter {
    As(AsId),
    Prefix(AddressPrefix),
}

impl Filter {
    /// Returns whether this filter covers this origin.
    fn covers(self, origin: &AddressOrigin) -> bool {
        match self {
            Filter::As(as_id) => origin.as_id() == as_id,
            Filter::Prefix(prefix) => origin.prefix().covers(prefix)
        }
    }
}

