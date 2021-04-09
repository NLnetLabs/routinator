//! Output of lists of VRPs.

// Some functions here have unnecessarily wrapped return types for
// consisitency.
#![allow(clippy::unnecessary_wraps)]

use std::io;
use std::str::FromStr;
use chrono::Utc;
use chrono::format::{Item, Numeric, Pad};
use log::error;
use rpki::repository::resources::AsId;
use crate::error::Failed;
use crate::metrics::Metrics;
use crate::payload::{AddressPrefix, OriginInfo, PayloadSnapshot, RouteOrigin};


//------------ OutputFormat --------------------------------------------------

/// The output format for VRPs.
#[derive(Clone, Copy, Debug)]
pub enum OutputFormat {
    /// CSV format.
    ///
    /// Each row has the AS number, prefix, max-length, and TA.
    Csv,

    /// RIPE NCC Validator compatible CSV format.
    ///
    /// This quotes all values and prints the AS number as just the number.
    CompatCsv,

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

    /// BIRD configuration format.
    ///
    /// Specifically, this produces as `roa table`.
    Bird1,

    /// BIRD2 configuration format.
    ///
    /// Specifically, this produces as `route table`.
    Bird2,

    /// RPSL output.
    ///
    /// This produces a sequence of RPSL objects with various fields.
    Rpsl,

    /// Summary output.
    ///
    /// Produces a textual summary of the ROAs and VRPS.
    Summary,

    /// No output.
    ///
    /// Seriously: no output.
    None,
}

impl OutputFormat {
    /// A list of the known output formats.
    pub const VALUES: &'static [&'static str] = &[
        "csv", "csvcompat", "csvext", "json", "openbgpd", "bird1", "bird2",
        "rpsl", "summary", "none"
    ];

    /// The default output format.
    pub const DEFAULT_VALUE: &'static str = "csv";
}

impl FromStr for OutputFormat {
    type Err = Failed;

    fn from_str(value: &str) -> Result<Self, Failed> {
        Self::try_from_str(value).ok_or_else(|| {
            error!("Unknown output format: {}", value);
            Failed
        })
    }
}

impl OutputFormat {
    /// Returns the output format for a string if any.
    pub fn try_from_str(value: &str) -> Option<Self> {
        match value {
            "csv" => Some(OutputFormat::Csv),
            "csvcompat" => Some(OutputFormat::CompatCsv),
            "csvext" => Some(OutputFormat::ExtendedCsv),
            "json" => Some(OutputFormat::Json),
            "openbgpd" => Some(OutputFormat::Openbgpd),
            "bird1" => Some(OutputFormat::Bird1),
            "bird2" => Some(OutputFormat::Bird2),
            "rpsl" => Some(OutputFormat::Rpsl),
            "summary" => Some(OutputFormat::Summary),
            "none" => Some(OutputFormat::None),
            _ => None,
        }
    }

    /// Returns the output format for a given request path.
    pub fn from_path(path: &str) -> Option<Self> {
        if !path.starts_with('/') {
            return None
        }
        Self::try_from_str(&path[1..])
    }

    /// Returns whether this output format requires extra output.
    pub fn extra_output(self) -> bool {
        matches!(self, OutputFormat::ExtendedCsv)
    }

    /// Returns whether this output format requires metrics.
    pub fn needs_metrics(self) -> bool {
        matches!(self, OutputFormat::Summary)
    }

    /// Creates an output stream for this format.
    pub fn stream<T, F, M>(
        self,
        origins: T,
        filters: Option<F>,
        metrics: M
    ) -> OutputStream<T, F, M> {
        OutputStream::new(origins, self, filters, metrics)
    }

    /// Outputs `vrps` to `target` in this format.
    ///
    /// This method loggs error messages.
    pub fn output<W: io::Write>(
        self,
        vrps: &PayloadSnapshot,
        filters: Option<&[Filter]>,
        metrics: &Metrics,
        target: &mut W,
    ) -> Result<(), io::Error> {
        match self.stream(vrps, filters, metrics).output(target) {
            Ok(()) => Ok(()),
            Err(ref err) if err.kind() == io::ErrorKind::BrokenPipe => Ok(()),
            Err(err) => Err(err)
        }
    }

    pub fn content_type(self) -> &'static str {
        match self {
            OutputFormat::Csv | OutputFormat::CompatCsv |
            OutputFormat::ExtendedCsv
                => "text/csv;charset=utf-8;header=present",
            OutputFormat::Json => "application/json",
            _ => "text/plain;charset=utf-8",
        }
    }
}


//------------ OutputStream --------------------------------------------------

pub struct OutputStream<T, F, M> {
    snapshot: T,
    next_id: usize,
    format: OutputFormat,
    filters: Option<F>,
    metrics: M,
} 

impl<T, F, M> OutputStream<T, F, M> {
    fn new(
        snapshot: T,
        format: OutputFormat,
        filters: Option<F>,
        metrics: M,
    ) -> Self {
        Self {
            snapshot,
            next_id: 0,
            format,
            filters,
            metrics
        }
    }
}

impl<T, F, M> OutputStream<T, F, M>
where
    T: AsRef<PayloadSnapshot>,
    F: AsRef<[Filter]>,
    M: AsRef<Metrics>
{
    pub fn output<W: io::Write>(
        &self,
        target: &mut W
    ) -> Result<(), io::Error> {
        self.output_header(target)?;
        let mut first = true;
        for item in self.snapshot.as_ref().origins() {
            if self.output_origin(item.0, &item.1, first, target)? {
                first = false;
            }
        }
        self.output_footer(target)
    }

    pub fn output_len(&self) -> usize {
        GetLength::get(|w| self.output(w).unwrap())
    }

    pub fn output_start<W: io::Write>(
        &mut self,
        target: &mut W
    ) -> Result<(), io::Error> {
        self.output_header(target)?;
        self.next_batch(true, target)
    }

    fn has_next_batch(&self) -> bool {
        self.next_id < self.snapshot.as_ref().origins().len()
    }

    fn next_batch<W: io::Write>(
        &mut self,
        mut first: bool,
        target: &mut W 
    ) -> Result<(), io::Error> {
        let origins = self.snapshot.as_ref().origins();
        let mut len = 0;
        while self.next_id < origins.len() && len < 1000 {
            let item = &origins[self.next_id];
            if self.output_origin(item.0, &item.1, first, target
            )? {
                first = false;
                len += 1;
            }
            self.next_id += 1;
        }
        if self.next_id == origins.len() {
            self.output_footer(target)?;
        }
        Ok(())
    }

    pub fn output_header<W: io::Write>(
        &self,
        target: &mut W
    ) -> Result<(), io::Error> {
        let vrps = self.snapshot.as_ref();
        match self.format {
            OutputFormat::Csv => csv_header(vrps, target),
            OutputFormat::CompatCsv => compat_csv_header(vrps, target),
            OutputFormat::ExtendedCsv => ext_csv_header(vrps, target),
            OutputFormat::Json => json_header(vrps, target),
            OutputFormat::Openbgpd => openbgpd_header(vrps, target),
            OutputFormat::Bird1 => bird1_header(vrps, target),
            OutputFormat::Bird2 => bird2_header(vrps, target),
            OutputFormat::Rpsl => rpsl_header(vrps, target),
            OutputFormat::Summary => summary_header(&self.metrics, target),
            OutputFormat::None => Ok(())
        }
    }

    pub fn output_origin<W: io::Write>(
        &self,
        vrp: RouteOrigin,
        info: &OriginInfo,
        first: bool,
        target: &mut W
    ) -> Result<bool, io::Error> {
        if self.skip_origin(vrp) {
            return Ok(false)
        }
        match self.format {
            OutputFormat::Csv => csv_origin(vrp, info, first, target)?,
            OutputFormat::CompatCsv => {
                compat_csv_origin(vrp, info, first, target)?
            }
            OutputFormat::ExtendedCsv => {
                ext_csv_origin(vrp, info, first, target)?
            }
            OutputFormat::Json => json_origin(vrp, info, first, target)?,
            OutputFormat::Openbgpd => {
                openbgpd_origin(vrp, info, first, target)?
            }
            OutputFormat::Bird1 => bird1_origin(vrp, info, first, target)?,
            OutputFormat::Bird2 => bird2_origin(vrp, info, first, target)?,
            OutputFormat::Rpsl => rpsl_origin(vrp, info, first, target)?,
            _ => { }
        }
        Ok(true)
    }

    fn skip_origin(
        &self, 
        origin: RouteOrigin,
    ) -> bool {
        match self.filters.as_ref() {
            Some(filters) => {
                for filter in filters.as_ref() {
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
        &self,
        target: &mut W
    ) -> Result<(), io::Error> {
        let vrps = self.snapshot.as_ref();
        match self.format {
            OutputFormat::Csv => csv_footer(vrps, target),
            OutputFormat::CompatCsv => compat_csv_footer(vrps, target),
            OutputFormat::ExtendedCsv => ext_csv_footer(vrps, target),
            OutputFormat::Json => json_footer(vrps, target),
            OutputFormat::Openbgpd => openbgpd_footer(vrps, target),
            OutputFormat::Bird1 => bird1_footer(vrps, target),
            OutputFormat::Bird2 => bird2_footer(vrps, target),
            OutputFormat::Rpsl => rpsl_footer(vrps, target),
            _ => Ok(())
        }
    }

}

impl<T, F, M> Iterator for OutputStream<T, F, M>
where
    T: AsRef<PayloadSnapshot>,
    F: AsRef<[Filter]>,
    M: AsRef<Metrics>
{
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Vec<u8>> {
        if self.next_id == 0 {
            let mut target = Vec::new();
            self.output_start(&mut target).unwrap();
            Some(target)
        }
        else if !self.has_next_batch() {
            None
        }
        else {
            let mut target = Vec::new();
            self.next_batch(false, &mut target).unwrap();
            Some(target)
        }
    }
}


//------------ csv -----------------------------------------------------------

fn csv_header<W: io::Write>(
    _vrps: &PayloadSnapshot,
    output: &mut W,
) -> Result<(), io::Error> {
    writeln!(output, "ASN,IP Prefix,Max Length,Trust Anchor")
}

fn csv_origin<W: io::Write>(
    addr: RouteOrigin,
    info: &OriginInfo,
    _first: bool,
    output: &mut W,
) -> Result<(), io::Error> {
    writeln!(output, "{},{}/{},{},{}",
        addr.as_id(),
        addr.address(), addr.address_length(),
        addr.max_length(),
        info.tal_name().unwrap_or("N/A"),
    )
}

fn csv_footer<W: io::Write>(
    _vrps: &PayloadSnapshot,
    _output: &mut W,
) -> Result<(), io::Error> {
    Ok(())
}


//------------ compat_csv ----------------------------------------------------

fn compat_csv_header<W: io::Write>(
    _vrps: &PayloadSnapshot,
    output: &mut W,
) -> Result<(), io::Error> {
    writeln!(output, "\"ASN\",\"IP Prefix\",\"Max Length\",\"Trust Anchor\"")
}

fn compat_csv_origin<W: io::Write>(
    addr: RouteOrigin,
    info: &OriginInfo,
    _first: bool,
    output: &mut W,
) -> Result<(), io::Error> {
    writeln!(output, "\"{}\",\"{}/{}\",\"{}\",\"{}\"",
        u32::from(addr.as_id()),
        addr.address(), addr.address_length(),
        addr.max_length(),
        info.tal_name().unwrap_or("N/A"),
    )
}

fn compat_csv_footer<W: io::Write>(
    _vrps: &PayloadSnapshot,
    _output: &mut W,
) -> Result<(), io::Error> {
    Ok(())
}


//------------ ext_csv -------------------------------------------------------

// 2017-08-25 13:12:19
const EXT_CSV_TIME_ITEMS: &[Item<'static>] = &[
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
    _vrps: &PayloadSnapshot,
    output: &mut W,
) -> Result<(), io::Error> {
    writeln!(output, "URI,ASN,IP Prefix,Max Length,Not Before,Not After")
}

fn ext_csv_origin<W: io::Write>(
    addr: RouteOrigin,
    info: &OriginInfo,
    _first: bool,
    output: &mut W,
) -> Result<(), io::Error> {
    write!(output, "{},{},{}/{},{},",
        info.uri().map(|uri| uri.as_str()).unwrap_or("N/A"),
        addr.as_id(),
        addr.address(), addr.address_length(),
        addr.max_length(),
    )?;
    match info.validity() {
        Some(validity) => {
            writeln!(output, "{},{}",
                validity.not_before().format_with_items(
                    EXT_CSV_TIME_ITEMS.iter().cloned()
                ),
                validity.not_after().format_with_items(
                    EXT_CSV_TIME_ITEMS.iter().cloned()
                )
            )
        }
        None => writeln!(output, "N/A,N/A"),
    }
}

fn ext_csv_footer<W: io::Write>(
    _vrps: &PayloadSnapshot,
    _output: &mut W,
) -> Result<(), io::Error> {
    Ok(())
}


//------------ json ----------------------------------------------------------

fn json_header<W: io::Write>(
    _vrps: &PayloadSnapshot,
    output: &mut W,
) -> Result<(), io::Error> {
    writeln!(output, "{{\n  \"roas\": [")
}

fn json_origin<W: io::Write>(
    addr: RouteOrigin,
    info: &OriginInfo,
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
        info.tal_name().unwrap_or("N/A"),
    )
}

fn json_footer<W: io::Write>(
    _vrps: &PayloadSnapshot,
    output: &mut W,
) -> Result<(), io::Error> {
    writeln!(output, "\n  ]\n}}")
}


//------------ openbgpd ------------------------------------------------------

fn openbgpd_header<W: io::Write>(
    _vrps: &PayloadSnapshot,
    output: &mut W,
) -> Result<(), io::Error> {
    writeln!(output, "roa-set {{")
}

fn openbgpd_origin<W: io::Write>(
    addr: RouteOrigin,
    _info: &OriginInfo,
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
    _vrps: &PayloadSnapshot,
    output: &mut W,
) -> Result<(), io::Error> {
    writeln!(output, "}}")
}


//------------ bird1 ------------------------------------------------------

fn bird1_header<W: io::Write>(
    _vrps: &PayloadSnapshot,
    _output: &mut W,
) -> Result<(), io::Error> {
    Ok(())
}

fn bird1_origin<W: io::Write>(
    addr: RouteOrigin,
    _info: &OriginInfo,
    _first: bool,
    output: &mut W,
) -> Result<(), io::Error> {
    writeln!(output, "roa {}/{} max {} as {};",
        addr.address(), addr.address_length(),
        addr.max_length(),
        u32::from(addr.as_id()))
}

fn bird1_footer<W: io::Write>(
    _vrps: &PayloadSnapshot,
    _output: &mut W,
) -> Result<(), io::Error> {
    Ok(())
}


//------------ bird2 ------------------------------------------------------

fn bird2_header<W: io::Write>(
    _vrps: &PayloadSnapshot,
    _output: &mut W,
) -> Result<(), io::Error> {
    Ok(())
}

fn bird2_origin<W: io::Write>(
    addr: RouteOrigin,
    _info: &OriginInfo,
    _first: bool,
    output: &mut W,
) -> Result<(), io::Error> {
    writeln!(output, "route {}/{} max {} as {};",
        addr.address(), addr.address_length(),
        addr.max_length(),
        u32::from(addr.as_id()))
}

fn bird2_footer<W: io::Write>(
    _vrps: &PayloadSnapshot,
    _output: &mut W,
) -> Result<(), io::Error> {
    Ok(())
}


//------------ rpsl ----------------------------------------------------------

// 2017-08-25T13:12:19Z
const RPSL_TIME_ITEMS: &[Item<'static>] = &[
    Item::Numeric(Numeric::Year, Pad::Zero),
    Item::Literal("-"),
    Item::Numeric(Numeric::Month, Pad::Zero),
    Item::Literal("-"),
    Item::Numeric(Numeric::Day, Pad::Zero),
    Item::Literal("T"),
    Item::Numeric(Numeric::Hour, Pad::Zero),
    Item::Literal(":"),
    Item::Numeric(Numeric::Minute, Pad::Zero),
    Item::Literal(":"),
    Item::Numeric(Numeric::Second, Pad::Zero),
    Item::Literal("Z"),
];

fn rpsl_header<W: io::Write>(
    _vrps: &PayloadSnapshot,
    _output: &mut W,
) -> Result<(), io::Error> {
    Ok(())
}

fn rpsl_origin<W: io::Write>(
    addr: RouteOrigin,
    info: &OriginInfo,
    _first: bool,
    output: &mut W,
) -> Result<(), io::Error> {
    let now = Utc::now().format_with_items(RPSL_TIME_ITEMS.iter().cloned());
    writeln!(output,
        "\n{}: {}/{}\norigin: {}\n\
        descr: RPKI attestation\nmnt-by: NA\ncreated: {}\n\
        last-modified: {}\nsource: ROA-{}-RPKI-ROOT\n",
        if addr.address().is_ipv4() { "route" }
        else { "route6" },
        addr.address(), addr.address_length(),
        addr.as_id(), now, now,
        info.tal_name().map(|name| {
            name.to_uppercase()
        }).unwrap_or_else(|| "N/A".into())
    )
}

fn rpsl_footer<W: io::Write>(
    _vrps: &PayloadSnapshot,
    _output: &mut W,
) -> Result<(), io::Error> {
    Ok(())
}


//------------ summary -------------------------------------------------------

fn summary_header<M: AsRef<Metrics>, W: io::Write>(
    metrics: &M,
    output: &mut W,
) -> Result<(), io::Error> {
    let metrics = metrics.as_ref();
    writeln!(output, "Summary at {}", metrics.time)?;
    for tal in &metrics.tals {
        writeln!(output,
            "{}: {} verified ROAs, {} verified VRPs, \
             {} unsafe VRPs, {} final VRPs.",
            tal.name(), tal.publication.valid_roas, tal.vrps.valid,
            tal.vrps.marked_unsafe, tal.vrps.contributed
        )?;
    }
    writeln!(output,
        "total: {} verified ROAs, {} verified VRPs, \
         {} unsafe VRPs, {} final VRPs.",
        metrics.publication.valid_roas,
        metrics.vrps.valid, metrics.vrps.marked_unsafe,
        metrics.vrps.contributed,
    )
}


//------------ Filter --------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub enum Filter {
    As(AsId),
    Prefix(AddressPrefix),
}

impl Filter {
    /// Returns whether this filter covers this origin.
    fn covers(self, origin: RouteOrigin) -> bool {
        match self {
            Filter::As(as_id) => origin.as_id() == as_id,
            Filter::Prefix(prefix) => origin.prefix().covers(prefix)
        }
    }
}


//------------ GetLength -----------------------------------------------------

/// A writer that adds up the length of whatever has been written.
#[derive(Clone, Copy, Debug, Default)]
struct GetLength(usize);

impl GetLength {
    /// Returns the length of what’s been written in the closure.
    ///
    /// The closure receives a writer it should write to.
    pub fn get<F: FnOnce(&mut Self)>(op: F) -> usize {
        let mut target = Self::default();
        op(&mut target);
        target.0
    }
}

impl io::Write for GetLength {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        self.0 += buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        Ok(())
    }
}

