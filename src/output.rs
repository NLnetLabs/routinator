//! Output of validated RPKI payload.

use std::{error, fmt, io};
use std::str::FromStr;
use std::sync::Arc;
use chrono::Utc;
use chrono::format::{Item, Numeric, Pad};
use log::error;
use rpki::repository::resources::AsId;
use crate::payload;
use crate::error::Failed;
use crate::payload::{AddressPrefix, OriginInfo, PayloadSnapshot, RouteOrigin};
use crate::metrics::Metrics;


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

    /// JSON format with extended information.
    ExtendedJson,

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
    /// All known output formats names and their values.
    const VALUES: &'static [(&'static str, Self)] = &[
        ("csv", OutputFormat::Csv),
        ("csvcompat", OutputFormat::CompatCsv),
        ("csvext", OutputFormat::ExtendedCsv),
        ("json", OutputFormat::Json),
        ("jsonext", OutputFormat::ExtendedJson),
        ("openbgpd", OutputFormat::Openbgpd),
        ("bird1", OutputFormat::Bird1),
        ("bird2", OutputFormat::Bird2),
        ("rpsl", OutputFormat::Rpsl),
        ("summary", OutputFormat::Summary),
        ("none", OutputFormat::None),
    ];

    /// The default output format name.
    pub const DEFAULT_VALUE: &'static str = "csv";
}

impl OutputFormat {
    /// Returns the output format for a given request path.
    pub fn from_path(path: &str) -> Option<Self> {
        if !path.starts_with('/') {
            return None
        }
        Self::try_from_str(&path[1..])
    }

    /// Returns the output format for the given string if it is valid.
    fn try_from_str(value: &str) -> Option<Self> {
        for &(name, res) in Self::VALUES {
            if name == value {
                return Some(res)
            }
        }
        None
    }

    /// Returns the media type string for this output format.
    pub fn content_type(self) -> &'static str {
        match self {
            OutputFormat::Csv | OutputFormat::CompatCsv |
            OutputFormat::ExtendedCsv
                => "text/csv;charset=utf-8;header=present",
            OutputFormat::Json | OutputFormat::ExtendedJson
                => "application/json",
            _ => "text/plain;charset=utf-8",
        }
    }

    /// Outputs a payload snapshot to a writer.
    pub fn output_snapshot<W: io::Write>(
        self,
        snapshot: &PayloadSnapshot,
        selection: Option<&Selection>,
        metrics: &Metrics,
        target: &mut W,
    ) -> Result<(), io::Error> {
        let mut stream = OutputStream::new(
            self, snapshot, selection, metrics
        );
        while stream.write_next(target)? { }
        Ok(())
    }

    /// Creates an output stream for this format.
    pub fn stream(
        self,
        snapshot: Arc<PayloadSnapshot>,
        selection: Option<Selection>,
        metrics: Arc<Metrics>,
    ) -> impl Iterator<Item = Vec<u8>> {
        OutputStream::new(self, snapshot, selection, metrics)
    }

    fn formatter<W: io::Write>(self) -> Box<dyn Formatter<W> + Send> {
        match self {
            OutputFormat::Csv => Box::new(Csv),
            OutputFormat::CompatCsv => Box::new(CompatCsv),
            OutputFormat::ExtendedCsv => Box::new(ExtendedCsv),
            OutputFormat::Json => Box::new(Json),
            OutputFormat::ExtendedJson => Box::new(ExtendedJson),
            OutputFormat::Openbgpd => Box::new(Openbgpd),
            OutputFormat::Bird1 => Box::new(Bird1),
            OutputFormat::Bird2 => Box::new(Bird2),
            OutputFormat::Rpsl => Box::new(Rpsl),
            OutputFormat::Summary => Box::new(Summary),
            OutputFormat::None => Box::new(NoOutput),
        }
    }
}


//--- FromStr

impl FromStr for OutputFormat {
    type Err = Failed;

    fn from_str(value: &str) -> Result<Self, Failed> {
        Self::try_from_str(value).ok_or_else(|| {
            error!("Unknown output format: {}", value);
            Failed
        })
    }
}


//------------ Selection -----------------------------------------------------

/// A set of rules defining which payload to include in output.
#[derive(Clone, Debug, Default)]
pub struct Selection {
    origins: Vec<SelectOrigin>,
}

impl Selection {
    /// Creates a new, empty selection.
    pub fn new() -> Self {
        Selection::default()
    }

    /// Creates a selection from a HTTP query string.
    pub fn from_query(query: Option<&str>) -> Result<Option<Self>, QueryError> {
        let query = match query {
            Some(query) => query,
            None => return Ok(None)
        };

        let mut res = Self::default();
        for (key, value) in form_urlencoded::parse(query.as_ref()) {
            if key == "select-prefix" || key == "filter-prefix" {
                res.origins.push(
                    SelectOrigin::Prefix(AddressPrefix::from_str(&value)?)
                );
            }
            else if key == "select-asn" || key == "filter-asn" {
                res.origins.push(
                    SelectOrigin::AsId(
                        AsId::from_str(&value).map_err(|_| QueryError)?
                    )
                );
            }
            else {
                return Err(QueryError)
            }
        }

        Ok(Some(res))
    }

    /// Add an origin ASN to select.
    pub fn push_origin_asn(&mut self, asn: AsId) {
        self.origins.push(SelectOrigin::AsId(asn))
    }

    /// Add a origin prefix to select.
    pub fn push_origin_prefix(&mut self, prefix: AddressPrefix) {
        self.origins.push(SelectOrigin::Prefix(prefix))
    }

    /// Returns whether payload should be included in output.
    pub fn include_origin(&self, origin: RouteOrigin) -> bool {
        for select in &self.origins {
            if select.include_origin(origin) {
                return true
            }
        }
        false
    }
}

impl AsRef<Selection> for Selection {
    fn as_ref(&self) -> &Self {
        self
    }
}


//------------ SelectOrigin --------------------------------------------------

/// A selection rule for origins.
#[derive(Clone, Copy, Debug)]
enum SelectOrigin {
    /// Include resources related to the given ASN.
    AsId(AsId),

    /// Include resources related to the given prefix.
    Prefix(AddressPrefix),
}

impl SelectOrigin {
    /// Returns whether this rule selects payload.
    fn include_origin(self, origin: RouteOrigin) -> bool {
        match self {
            SelectOrigin::AsId(as_id) => origin.as_id() == as_id,
            SelectOrigin::Prefix(prefix) => origin.prefix().covers(prefix),
        }
    }
}


//------------ OutputStream --------------------------------------------------

struct OutputStream<Snap, Sel, Met, Target> {
    snapshot: Snap,
    state: StreamState,
    formatter: Box<dyn Formatter<Target> + Send>,
    selection: Option<Sel>,
    metrics: Met,
}

enum StreamState {
    Header,
    Origin { index: usize, first: bool },
    Done,
}

impl<Snap, Sel, Met, Target> OutputStream<Snap, Sel, Met, Target>
where
    Snap: AsRef<PayloadSnapshot>,
    Sel: AsRef<Selection>,
    Met: AsRef<Metrics>,
    Target: io::Write,
{
    /// Creates a new output stream.
    fn new(
        format: OutputFormat,
        snapshot: Snap,
        selection: Option<Sel>,
        metrics: Met,
    ) -> Self {
        OutputStream {
            snapshot,
            state: StreamState::Header,
            formatter: format.formatter(),
            selection,
            metrics,
        }
    }

    /// Writes the next item to the target.
    ///
    /// Returns whether it wrote an item.
    fn write_next(&mut self, target: &mut Target) -> Result<bool, io::Error> {
        match self.state {
            StreamState::Header => {
                self.formatter.header(
                    self.snapshot.as_ref(), self.metrics.as_ref(), target
                )?;
                self.state = StreamState::Origin { index: 0, first: true };
                Ok(true)
            }
            StreamState::Origin { mut index, first } => {
                loop {
                    let (origin, info) = match
                        self.snapshot.as_ref().origins().get(index)
                    {
                        Some(item) => (item.0, &item.1),
                        None => {
                            self.formatter.footer(
                                self.metrics.as_ref(), target
                            )?;
                            self.state = StreamState::Done;
                            break
                        }
                    };
                    index += 1;
                    if let Some(selection) = self.selection.as_ref() {
                        if !selection.as_ref().include_origin(origin) {
                            continue
                        }
                    }
                    if !first {
                        self.formatter.delimiter(target)?;
                    }
                    self.formatter.origin(origin, info, target)?;
                    self.state = StreamState::Origin { index, first: false };
                    break
                }
                Ok(true)
            }
            StreamState::Done => Ok(false)
        }
    }
}

impl Iterator for OutputStream<
    Arc<PayloadSnapshot>, Selection, Arc<Metrics>, Vec<u8>
> {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut res = Vec::new();
        while self.write_next(&mut res).expect("write to vec failed") {
            if res.len() > 64000 {
                return Some(res)
            }
        }
        if res.is_empty() {
            None
        }
        else {
            Some(res)
        }
    }
}


//------------ QueryError ----------------------------------------------------

#[derive(Debug)]
pub struct QueryError;

impl From<payload::FromStrError> for QueryError {
    fn from(_: payload::FromStrError) -> Self {
        QueryError
    }
}

impl fmt::Display for QueryError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("invalid query")
    }
}

impl error::Error for QueryError { }


//------------ Formatter -----------------------------------------------------

trait Formatter<W> {
    fn header(
        &self, snapshot: &PayloadSnapshot, metrics: &Metrics, target: &mut W
    ) -> Result<(), io::Error> {
        let _ = (snapshot, metrics, target);
        Ok(())
    }

    fn footer(
        &self, metrics: &Metrics, target: &mut W
    ) -> Result<(), io::Error> {
        let _ = (metrics, target);
        Ok(())
    }

    fn origin(
        &self, origin: RouteOrigin, info: &OriginInfo, target: &mut W
    ) -> Result<(), io::Error>;

    fn delimiter(&self, target: &mut W) -> Result<(), io::Error> {
        let _ = target;
        Ok(())
    }
}


//------------ Csv -----------------------------------------------------------

struct Csv;

impl<W: io::Write> Formatter<W> for Csv {
    fn header(
        &self, _snapshot: &PayloadSnapshot, _metrics: &Metrics, target: &mut W
    ) -> Result<(), io::Error> {
        writeln!(target, "ASN,IP Prefix,Max Length,Trust Anchor")
    }

    fn origin(
        &self, origin: RouteOrigin, info: &OriginInfo, target: &mut W
    ) -> Result<(), io::Error> {
        writeln!(target, "{},{}/{},{},{}",
            origin.as_id(),
            origin.address(), origin.address_length(),
            origin.max_length(),
            info.tal_name().unwrap_or("N/A"),
        )
    }
}


//------------ CompatCsv -----------------------------------------------------

struct CompatCsv;

impl<W: io::Write> Formatter<W> for CompatCsv {
    fn header(
        &self, _snapshot: &PayloadSnapshot, _metrics: &Metrics, target: &mut W
    ) -> Result<(), io::Error> {
        writeln!(
            target, "\"ASN\",\"IP Prefix\",\"Max Length\",\"Trust Anchor\""
        )
    }

    fn origin(
        &self, origin: RouteOrigin, info: &OriginInfo, target: &mut W
    ) -> Result<(), io::Error> {
        writeln!(target, "\"{}\",\"{}/{}\",\"{}\",\"{}\"",
            origin.as_id(),
            origin.address(), origin.address_length(),
            origin.max_length(),
            info.tal_name().unwrap_or("N/A"),
        )
    }
}


//------------ ExtendedCsv ---------------------------------------------------

struct ExtendedCsv;

impl ExtendedCsv {
    // 2017-08-25 13:12:19
    const TIME_ITEMS: &'static [Item<'static>] = &[
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
}

impl<W: io::Write> Formatter<W> for ExtendedCsv {
    fn header(
        &self, _snapshot: &PayloadSnapshot, _metrics: &Metrics, target: &mut W
    ) -> Result<(), io::Error> {
        writeln!(target, "URI,ASN,IP Prefix,Max Length,Not Before,Not After")
    }

    fn origin(
        &self, origin: RouteOrigin, info: &OriginInfo, target: &mut W
    ) -> Result<(), io::Error> {
        write!(target, "{},{},{}/{},{},",
            info.uri().map(|uri| uri.as_str()).unwrap_or("N/A"),
            origin.as_id(),
            origin.address(), origin.address_length(),
            origin.max_length(),
        )?;
        match info.validity() {
            Some(validity) => {
                writeln!(target, "{},{}",
                    validity.not_before().format_with_items(
                        Self::TIME_ITEMS.iter().cloned()
                    ),
                    validity.not_after().format_with_items(
                        Self::TIME_ITEMS.iter().cloned()
                    )
                )
            }
            None => writeln!(target, "N/A,N/A"),
        }
    }
}


//------------ Json ----------------------------------------------------------

struct Json;

impl<W: io::Write> Formatter<W> for Json {
    fn header(
        &self, _snapshot: &PayloadSnapshot, _metrics: &Metrics, target: &mut W
    ) -> Result<(), io::Error> {
        writeln!(target, "{{\n  \"roas\": [")
    }

    fn footer(
        &self, _metrics: &Metrics, target: &mut W
    ) -> Result<(), io::Error> {
        writeln!(target, "\n  ]\n}}")
    }

    fn origin(
        &self, origin: RouteOrigin, info: &OriginInfo, target: &mut W
    ) -> Result<(), io::Error> {
        write!(target,
            "    {{ \"asn\": \"{}\", \"prefix\": \"{}/{}\", \
            \"maxLength\": {}, \"ta\": \"{}\" }}",
            origin.as_id(),
            origin.address(), origin.address_length(),
            origin.max_length(),
            info.tal_name().unwrap_or("N/A"),
        )
    }

    fn delimiter(&self, target: &mut W) -> Result<(), io::Error> {
        writeln!(target, ",")
    }
}


//------------ ExtendedJson --------------------------------------------------

struct ExtendedJson;

impl ExtendedJson {
    // 2017-08-25T13:12:19Z
    const TIME_ITEMS: &'static [Item<'static>] = &[
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
}

impl<W: io::Write> Formatter<W> for ExtendedJson {
    fn header(
        &self, _snapshot: &PayloadSnapshot, _metrics: &Metrics, target: &mut W
    ) -> Result<(), io::Error> {
        writeln!(target, "{{\n  \"roas\": [")
    }

    fn footer(
        &self, _metrics: &Metrics, target: &mut W
    ) -> Result<(), io::Error> {
        writeln!(target, "\n  ]\n}}")
    }

    fn origin(
        &self, origin: RouteOrigin, info: &OriginInfo, target: &mut W
    ) -> Result<(), io::Error> {
        write!(target,
            "    {{ \"asn\": \"{}\", \"prefix\": \"{}/{}\", \
            \"maxLength\": {}, \"source\": [",
            origin.as_id(),
            origin.address(), origin.address_length(),
            origin.max_length(),
        )?;

        let mut first = true;
        for item in info {
            if let Some(roa) = item.roa_info() {
                if !first {
                    write!(target, ", ")?;
                }
                else {
                    first = false;
                }
                write!(target, " {{ \"type\": \"roa\", \"uri\": ")?;
                match roa.uri.as_ref() {
                    Some(uri) => write!(target, "\"{}\"", uri)?,
                    None => write!(target, "null")?
                }

                write!(target,
                    ", \"validity\": {{ \"notBefore\": \"{}\", \
                    \"notAfter\": \"{}\" }}, \
                    \"chainValidity\": {{ \"notBefore\": \"{}\", \
                    \"notAfter\": \"{}\" }} \
                    }}",
                    roa.roa_validity.not_before().format_with_items(
                        Self::TIME_ITEMS.iter().cloned()
                    ),
                    roa.roa_validity.not_after().format_with_items(
                        Self::TIME_ITEMS.iter().cloned()
                    ),
                    roa.chain_validity.not_before().format_with_items(
                        Self::TIME_ITEMS.iter().cloned()
                    ),
                    roa.chain_validity.not_after().format_with_items(
                        Self::TIME_ITEMS.iter().cloned()
                    )
                )?;
            }
            if let Some(exc) = item.exception_info() {
                if !first {
                    write!(target, ", ")?;
                }
                else {
                    first = false;
                }
                write!(target, " {{ \"type\": \"exception\", \"path\": ")?;
                match exc.path.as_ref() {
                    Some(path) => write!(target, "\"{}\"", path.display())?,
                    None => write!(target, "null")?,
                }
                if let Some(comment) = exc.comment.as_ref() {
                    write!(target, ", \"comment\": \"{}\"", comment)?
                }
                write!(target, " }}")?;
            }
        }

        write!(target, "] }}")
    }

    fn delimiter(&self, target: &mut W) -> Result<(), io::Error> {
        writeln!(target, ",")
    }
}


//------------ Openbgpd ------------------------------------------------------

struct Openbgpd;

impl<W: io::Write> Formatter<W> for Openbgpd {
    fn header(
        &self, _snapshot: &PayloadSnapshot, _metrics: &Metrics, target: &mut W
    ) -> Result<(), io::Error> {
        writeln!(target, "roa-set {{")
    }

    fn footer(
        &self, _metrics: &Metrics, target: &mut W
    ) -> Result<(), io::Error> {
        writeln!(target, "}}")
    }

    fn origin(
        &self, origin: RouteOrigin, _info: &OriginInfo, target: &mut W
    ) -> Result<(), io::Error> {
        write!(
            target, "    {}/{}", origin.address(), origin.address_length()
        )?;
        if origin.address_length() < origin.max_length() {
            write!(target, " maxlen {}", origin.max_length())?;
        }
        writeln!(target, " source-as {}", u32::from(origin.as_id()))
    }
}


//------------ Bird1 ---------------------------------------------------------

struct Bird1;

impl<W: io::Write> Formatter<W> for Bird1 {
    fn origin(
        &self, origin: RouteOrigin, _info: &OriginInfo, target: &mut W
    ) -> Result<(), io::Error> {
        writeln!(target, "roa {}/{} max {} as {};",
            origin.address(), origin.address_length(),
            origin.max_length(),
            u32::from(origin.as_id())
        )
    }
}


//------------ Bird2 ---------------------------------------------------------

struct Bird2;

impl<W: io::Write> Formatter<W> for Bird2 {
    fn origin(
        &self, origin: RouteOrigin, _info: &OriginInfo, target: &mut W
    ) -> Result<(), io::Error> {
        writeln!(target, "route {}/{} max {} as {};",
            origin.address(), origin.address_length(),
            origin.max_length(),
            u32::from(origin.as_id())
        )
    }
}


//------------ Rpsl ----------------------------------------------------------

struct Rpsl;

impl Rpsl {
    const TIME_ITEMS: &'static [Item<'static>] = &[
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
}

impl<W: io::Write> Formatter<W> for Rpsl {
    fn origin(
        &self, origin: RouteOrigin, info: &OriginInfo, target: &mut W
    ) -> Result<(), io::Error> {
        let now = Utc::now().format_with_items(
            Self::TIME_ITEMS.iter().cloned()
        );
        writeln!(target,
            "\n{}: {}/{}\norigin: {}\n\
            descr: RPKI attestation\nmnt-by: NA\ncreated: {}\n\
            last-modified: {}\nsource: ROA-{}-RPKI-ROOT\n",
            if origin.address().is_ipv4() { "route" }
            else { "route6" },
            origin.address(), origin.address_length(),
            origin.as_id(), now, now,
            info.tal_name().map(|name| {
                name.to_uppercase()
            }).unwrap_or_else(|| "N/A".into())
        )
    }
}



//------------ Summary -------------------------------------------------------

struct Summary;

impl<W: io::Write> Formatter<W> for Summary {
    fn header(
        &self, _snapshot: &PayloadSnapshot, metrics: &Metrics, target: &mut W
    ) -> Result<(), io::Error> {
        writeln!(target, "Summary at {}", metrics.time)?;
        for tal in &metrics.tals {
            writeln!(target,
                "{}: {} verified ROAs, {} verified VRPs, \
                 {} unsafe VRPs, {} final VRPs.",
                tal.name(), tal.publication.valid_roas, tal.vrps.valid,
                tal.vrps.marked_unsafe, tal.vrps.contributed
            )?;
        }
        writeln!(target,
            "total: {} verified ROAs, {} verified VRPs, \
             {} unsafe VRPs, {} final VRPs.",
            metrics.publication.valid_roas,
            metrics.vrps.valid, metrics.vrps.marked_unsafe,
            metrics.vrps.contributed,
        )
    }

    fn origin(
        &self, _origin: RouteOrigin, _info: &OriginInfo, _target: &mut W
    ) -> Result<(), io::Error> {
        Ok(())
    }
}



//------------ NoOutput-------------------------------------------------------

struct NoOutput;

impl<W: io::Write> Formatter<W> for NoOutput {
    fn origin(
        &self, _origin: RouteOrigin, _info: &OriginInfo, _target: &mut W
    ) -> Result<(), io::Error> {
        Ok(())
    }
}


