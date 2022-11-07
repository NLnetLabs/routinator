//! Output of validated RPKI payload.

use std::{error, fmt, io};
use std::io::Write;
use std::str::FromStr;
use std::sync::Arc;
use chrono::Utc;
use chrono::format::{Item, Numeric, Pad};
use log::{error, info};
use routecore::addr;
use rpki::repository::resources::Asn;
use rpki::rtr::payload::{RouteOrigin, RouterKey};
use crate::error::Failed;
use crate::http::ContentType;
use crate::payload::{
    PayloadInfo, PayloadSnapshot, SnapshotArcOriginsIter,
    SnapshotArcRouterKeysIter,
};
use crate::metrics::Metrics;
use crate::utils::date::format_iso_date;
use crate::utils::json::json_str;


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

    /// JSON format using the SLURM scheme.
    Slurm,

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
        ("slurm", OutputFormat::Slurm),
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
    pub fn content_type(self) -> ContentType {
        match self {
            OutputFormat::Csv | OutputFormat::CompatCsv |
            OutputFormat::ExtendedCsv
                => ContentType::CSV,
            OutputFormat::Json | OutputFormat::ExtendedJson |
            OutputFormat::Slurm
                => ContentType::JSON,
            _ => ContentType::TEXT,
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
        let formatter = self.formatter();
        let mut first = true;
        formatter.header(snapshot, metrics, target)?;
        for (origin, info) in snapshot.origins() {
            if let Some(selection) = selection {
                if !selection.include_origin(origin) {
                    continue
                }
            }
            if first {
                first = false;
            }
            else {
                formatter.delimiter(target)?;
            }
            formatter.origin(origin, info, target)?;
        }
        formatter.intermission(target)?;
        let mut first = true;
        for (key, info) in snapshot.router_keys() {
            if let Some(selection) = selection {
                if !selection.include_router_key(key) {
                    continue
                }
            }
            if first {
                first = false;
            }
            else {
                formatter.delimiter(target)?;
            }
            formatter.router_key(key, info, target)?;
        }
        formatter.footer(metrics, target)
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
            OutputFormat::Slurm => Box::new(Slurm),
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
    /// The list of selection conditions.
    origins: Vec<SelectOrigin>,

    /// Should we include more specific prefixes in the output?
    more_specifics: bool,
}

impl Selection {
    /// Creates a new, empty selection.
    pub fn new() -> Self {
        Selection::default()
    }

    /// Sets whether to include more specific prefixes.
    pub fn set_more_specifics(&mut self, more_specifics: bool) {
        self.more_specifics = more_specifics
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
                    SelectOrigin::Prefix(addr::Prefix::from_str(&value)?)
                );
            }
            else if key == "select-asn" || key == "filter-asn" {
                res.origins.push(
                    SelectOrigin::Asn(
                        Asn::from_str(&value).map_err(|_| QueryError)?
                    )
                );
            }
            else if key == "include" {
                for value in value.split(',') {
                    #[allow(clippy::single_match)]
                    match value {
                        "more-specifics" => res.more_specifics = true,
                        _ => { }
                    }
                }
            }
            else {
                return Err(QueryError)
            }
        }

        Ok(Some(res))
    }

    /// Add an origin ASN to select.
    pub fn push_origin_asn(&mut self, asn: Asn) {
        self.origins.push(SelectOrigin::Asn(asn))
    }

    /// Add a origin prefix to select.
    pub fn push_origin_prefix(&mut self, prefix: addr::Prefix) {
        self.origins.push(SelectOrigin::Prefix(prefix))
    }

    /// Returns whether an origin should be included in output.
    pub fn include_origin(&self, origin: RouteOrigin) -> bool {
        for select in &self.origins {
            if select.include_origin(origin, self.more_specifics) {
                return true
            }
        }
        false
    }

    /// Returns whether a router key should be included in output.
    pub fn include_router_key(&self, key: &RouterKey) -> bool {
        for select in &self.origins {
            if select.include_router_key(key) {
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
    Asn(Asn),

    /// Include resources related to the given prefix.
    Prefix(addr::Prefix),
}

impl SelectOrigin {
    /// Returns whether this rule selects payload.
    fn include_origin(
        self, origin: RouteOrigin, more_specifics: bool
    ) -> bool {
        match self {
            SelectOrigin::Asn(asn) => origin.asn == asn,
            SelectOrigin::Prefix(prefix) => {
                origin.prefix.prefix().covers(prefix)
                || (more_specifics && prefix.covers(origin.prefix.prefix()))
            }
        }
    }

    fn include_router_key(self, key: &RouterKey) -> bool {
        match self {
            SelectOrigin::Asn(asn) => key.asn == asn,
            _ => false
        }
    }
}


//------------ OutputStream --------------------------------------------------

struct OutputStream<Target> {
    snapshot: Arc<PayloadSnapshot>,
    state: StreamState,
    formatter: Box<dyn Formatter<Target> + Send>,
    selection: Option<Selection>,
    metrics: Arc<Metrics>,
}

enum StreamState {
    Header,
    Origin { iter: SnapshotArcOriginsIter, first: bool },
    Key { iter: SnapshotArcRouterKeysIter, first: bool },
    Done,
}

impl<Target: io::Write> OutputStream<Target> {
    /// Creates a new output stream.
    fn new(
        format: OutputFormat,
        snapshot: Arc<PayloadSnapshot>,
        selection: Option<Selection>,
        metrics: Arc<Metrics>,
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
    /// Returns `Ok(true)` if something was written and there may be more
    /// data. Returns `Ok(false)` if nothing was written and there also is
    /// no more data.
    fn write_next(&mut self, target: &mut Target) -> Result<bool, io::Error> {
        let next = match self.state {
            StreamState::Header => {
                self.formatter.header(
                    &self.snapshot, &self.metrics, target
                )?;
                StreamState::Origin {
                    iter: self.snapshot.clone().arc_origins_iter(),
                    first: true,
                }
            }
            StreamState::Origin { ref mut iter, ref mut first } => {
                loop {
                    let (origin, info) = match iter.next_with_info() {
                        Some((origin, info)) => (origin, info),
                        None => {
                            self.formatter.intermission(target)?;
                            break
                        }
                    };
                    if let Some(selection) = self.selection.as_ref() {
                        if !selection.include_origin(origin) {
                            continue
                        }
                    }
                    if *first {
                        *first = false;
                    }
                    else {
                        self.formatter.delimiter(target)?;
                    }
                    self.formatter.origin(origin, info, target)?;
                    return Ok(true)
                }
                StreamState::Key {
                    iter: self.snapshot.clone().arc_router_keys_iter(),
                    first: true
                }
            }
            StreamState::Key { ref mut iter, ref mut first } => {
                loop {
                    let (key, info) = match iter.next_with_info() {
                        Some((key, info)) => (key, info),
                        None => {
                            self.formatter.footer(
                                self.metrics.as_ref(), target
                            )?;
                            break
                        }
                    };
                    if let Some(selection) = self.selection.as_ref() {
                        if !selection.include_router_key(key) {
                            continue
                        }
                    }
                    if *first {
                        *first = false;
                    }
                    else {
                        self.formatter.delimiter(target)?;
                    }
                    self.formatter.router_key(key, info, target)?;
                    return Ok(true)
                }
                StreamState::Done
            }
            StreamState::Done => return Ok(false)
        };
        self.state = next;
        Ok(true)
    }
}

impl Iterator for OutputStream<Vec<u8>> {
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

impl From<addr::ParsePrefixError> for QueryError {
    fn from(_: addr::ParsePrefixError) -> Self {
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

    fn origin(
        &self, origin: RouteOrigin, info: &PayloadInfo, target: &mut W
    ) -> Result<(), io::Error>;

    fn intermission(
        &self, _target: &mut W
    ) -> Result<(), io::Error> {
        Ok(())
    }

    fn router_key(
        &self, _key: &RouterKey, _info: &PayloadInfo, _target: &mut W
    ) -> Result<(), io::Error> {
        Ok(())
    }

    fn footer(
        &self, metrics: &Metrics, target: &mut W
    ) -> Result<(), io::Error> {
        let _ = (metrics, target);
        Ok(())
    }

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
        &self, origin: RouteOrigin, info: &PayloadInfo, target: &mut W
    ) -> Result<(), io::Error> {
        writeln!(target, "{},{}/{},{},{}",
            origin.asn,
            origin.prefix.addr(), origin.prefix.prefix_len(),
            origin.prefix.resolved_max_len(),
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
        &self, origin: RouteOrigin, info: &PayloadInfo, target: &mut W
    ) -> Result<(), io::Error> {
        writeln!(target, "\"{}\",\"{}/{}\",\"{}\",\"{}\"",
            origin.asn,
            origin.prefix.addr(), origin.prefix.prefix_len(),
            origin.prefix.resolved_max_len(),
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
        &self, origin: RouteOrigin, info: &PayloadInfo, target: &mut W
    ) -> Result<(), io::Error> {
        write!(target, "{},{},{}/{},{},",
            info.uri().map(|uri| uri.as_str()).unwrap_or("N/A"),
            origin.asn,
            origin.prefix.addr(), origin.prefix.prefix_len(),
            origin.prefix.resolved_max_len(),
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
        &self, _snapshot: &PayloadSnapshot, metrics: &Metrics, target: &mut W
    ) -> Result<(), io::Error> {
        writeln!(target,
            "{{\
            \n  \"metadata\": {{\
            \n    \"generated\": {},\
            \n    \"generatedTime\": \"{}\"\
            \n  }},\
            \n  \"roas\": [",
            metrics.time.timestamp(),
            format_iso_date(metrics.time)
        )
    }

    fn footer(
        &self, _metrics: &Metrics, target: &mut W
    ) -> Result<(), io::Error> {
        writeln!(target, "\n  ]\n}}")
    }

    fn origin(
        &self, origin: RouteOrigin, info: &PayloadInfo, target: &mut W
    ) -> Result<(), io::Error> {
        write!(target,
            "    {{ \"asn\": \"{}\", \"prefix\": \"{}/{}\", \
            \"maxLength\": {}, \"ta\": \"{}\" }}",
            origin.asn,
            origin.prefix.addr(), origin.prefix.prefix_len(),
            origin.prefix.resolved_max_len(),
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
    fn payload_info(
        info: &PayloadInfo, rpki_type: &str, target: &mut impl io::Write
    ) -> Result<(), io::Error> {
        let mut first = true;
        for item in info {
            if let Some(roa) = item.publish_info() {
                if !first {
                    write!(target, ", ")?;
                }
                else {
                    first = false;
                }
                write!(target,
                    " {{ \"type\": \"{}\", \"uri\": ",
                    rpki_type,
                )?;
                match roa.uri.as_ref() {
                    Some(uri) => write!(target, "\"{}\"", uri)?,
                    None => write!(target, "null")?
                }

                write!(target,
                    ", \"tal\": \"{}\", \
                    \"validity\": {{ \"notBefore\": \"{}\", \
                    \"notAfter\": \"{}\" }}, \
                    \"chainValidity\": {{ \"notBefore\": \"{}\", \
                    \"notAfter\": \"{}\" }} \
                    }}",
                    json_str(roa.tal.name()),
                    format_iso_date(roa.roa_validity.not_before().into()),
                    format_iso_date(roa.roa_validity.not_after().into()),
                    format_iso_date(roa.chain_validity.not_before().into()),
                    format_iso_date(roa.chain_validity.not_after().into()),
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
                    Some(path) => {
                        write!(target, "\"{}\"", json_str(path.display()))?
                    }
                    None => write!(target, "null")?,
                }
                if let Some(comment) = exc.comment.as_ref() {
                    write!(
                        target, ", \"comment\": \"{}\"", json_str(comment)
                    )?
                }
                write!(target, " }}")?;
            }
        }
        Ok(())
    }
}

impl<W: io::Write> Formatter<W> for ExtendedJson {
    fn header(
        &self, _snapshot: &PayloadSnapshot, metrics: &Metrics, target: &mut W
    ) -> Result<(), io::Error> {
        writeln!(target,
            "{{\
            \n  \"metadata\": {{\
            \n    \"generated\": {},\
            \n    \"generatedTime\": \"{}\"\
            \n  }},\
            \n  \"roas\": [",
            metrics.time.timestamp(),
            format_iso_date(metrics.time)
        )
    }

    fn origin(
        &self, origin: RouteOrigin, info: &PayloadInfo, target: &mut W
    ) -> Result<(), io::Error> {
        write!(target,
            "    {{ \"asn\": \"{}\", \"prefix\": \"{}/{}\", \
            \"maxLength\": {}, \"source\": [",
            origin.asn,
            origin.prefix.addr(), origin.prefix.prefix_len(),
            origin.prefix.resolved_max_len(),
        )?;
        Self::payload_info(info, "roa", target)?;
        write!(target, "] }}")
    }

    fn intermission(&self, target: &mut W) -> Result<(), io::Error> {
        writeln!(target, "\n  ],\n  \"routerKeys\": [")
    }

    fn router_key(
        &self, key: &RouterKey, info: &PayloadInfo, target: &mut W
    ) -> Result<(), io::Error> {
        write!(target,
            "    {{ \"asn\": \"{}\", \"SKI\": \"{}\", \
            \"routerPublicKey\": \"{}\", \"source\": [",
            key.asn,
            key.key_identifier,
            key.key_info,
        )?;
        Self::payload_info(info, "cer", target)?;
        write!(target, "] }}")
    }

    fn footer(
        &self, _metrics: &Metrics, target: &mut W
    ) -> Result<(), io::Error> {
        writeln!(target, "\n  ]\n}}")
    }

    fn delimiter(&self, target: &mut W) -> Result<(), io::Error> {
        writeln!(target, ",")
    }
}


//------------ Slurm ---------------------------------------------------------

struct Slurm;

impl<W: io::Write> Formatter<W> for Slurm {
    fn header(
        &self, _snapshot: &PayloadSnapshot, _metrics: &Metrics, target: &mut W
    ) -> Result<(), io::Error> {
        writeln!(target,
            "{{\
            \n  \"slurmVersion\": 1,\
            \n  \"validationOutputFilters\": {{\
            \n    \"prefixFilters\": [ ],\
            \n    \"bgpsecFilters\": [ ]\
            \n  }},\
            \n  \"locallyAddedAssertions\": {{\
            \n    \"prefixAssertions\": ["
        )
    }

    fn origin(
        &self, origin: RouteOrigin, info: &PayloadInfo, target: &mut W
    ) -> Result<(), io::Error> {
        writeln!(target,
            "      {{\
            \n        \"asn\": {},\
            \n        \"prefix\": \"{}/{}\",",
            origin.asn.into_u32(),
            origin.prefix.addr(), origin.prefix.prefix_len()
        )?;
        if let Some(max_len) = origin.prefix.max_len() {
            writeln!(target, "        \"maxPrefixLength\": {},", max_len)?;
        }
        write!(target,
            "        \"comment\": \"{}\"\
            \n      }}",
            info.tal_name().unwrap_or("N/A")
        )
    }

    fn intermission(&self, target: &mut W) -> Result<(), io::Error> {
        writeln!(target,
            "\n    ],\
             \n    \"bgpsecAssertions\": ["
        )
    }

    fn router_key(
        &self, key: &RouterKey, info: &PayloadInfo, target: &mut W
    ) -> Result<(), io::Error> {
        write!(target,
             "      {{\
            \n        \"asn\": {},\
            \n        \"SKI\": \"",
            key.asn.into_u32(),
        )?;
        let mut enc = base64::write::EncoderWriter::new(
            target, base64::URL_SAFE_NO_PAD
        );
        enc.write_all(key.key_identifier.as_slice())?;
        let target = enc.finish()?;
        write!(target, "\",\
            \n        \"routerPublicKey\": \""
        )?;
        let mut enc = base64::write::EncoderWriter::new(
            target, base64::URL_SAFE_NO_PAD
        );
        enc.write_all(key.key_identifier.as_slice())?;
        let target = enc.finish()?;
        write!(target, "\",\
            \n        \"comment\": \"{}\"
            \n      }}",
            info.tal_name().unwrap_or("N/A")
        )
    }

    fn footer(
        &self, _metrics: &Metrics, target: &mut W
    ) -> Result<(), io::Error> {
        writeln!(target,
           "\n    ]\
            \n  }}\
            \n}}"
        )
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
        &self, origin: RouteOrigin, _info: &PayloadInfo, target: &mut W
    ) -> Result<(), io::Error> {
        write!(
            target, "    {}/{}",
            origin.prefix.addr(), origin.prefix.prefix_len(),
        )?;
        let max_len = origin.prefix.resolved_max_len();
        if origin.prefix.prefix_len() < max_len {
            write!(target, " maxlen {}", max_len)?;
        }
        writeln!(target, " source-as {}", u32::from(origin.asn))
    }
}


//------------ Bird1 ---------------------------------------------------------

struct Bird1;

impl<W: io::Write> Formatter<W> for Bird1 {
    fn origin(
        &self, origin: RouteOrigin, _info: &PayloadInfo, target: &mut W
    ) -> Result<(), io::Error> {
        writeln!(target, "roa {}/{} max {} as {};",
            origin.prefix.addr(), origin.prefix.prefix_len(),
            origin.prefix.resolved_max_len(),
            u32::from(origin.asn)
        )
    }
}


//------------ Bird2 ---------------------------------------------------------

struct Bird2;

impl<W: io::Write> Formatter<W> for Bird2 {
    fn origin(
        &self, origin: RouteOrigin, _info: &PayloadInfo, target: &mut W
    ) -> Result<(), io::Error> {
        writeln!(target, "route {}/{} max {} as {};",
            origin.prefix.addr(), origin.prefix.prefix_len(),
            origin.prefix.resolved_max_len(),
            u32::from(origin.asn)
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
        &self, origin: RouteOrigin, info: &PayloadInfo, target: &mut W
    ) -> Result<(), io::Error> {
        let now = Utc::now().format_with_items(
            Self::TIME_ITEMS.iter().cloned()
        );
        writeln!(target,
            "\n{}: {}/{}\norigin: {}\n\
            descr: RPKI attestation\nmnt-by: NA\ncreated: {}\n\
            last-modified: {}\nsource: ROA-{}-RPKI-ROOT\n",
            if origin.prefix.addr().is_ipv4() { "route" }
            else { "route6" },
            origin.prefix.addr(), origin.prefix.prefix_len(),
            origin.asn, now, now,
            info.tal_name().map(|name| {
                name.to_uppercase()
            }).unwrap_or_else(|| "N/A".into())
        )
    }
}



//------------ Summary -------------------------------------------------------

/// Output only a summary.
pub struct Summary;

impl Summary {
    fn produce_header(
        metrics: &Metrics,
        mut line: impl FnMut(fmt::Arguments) -> Result<(), io::Error>
    ) -> Result<(), io::Error> {
        line(format_args!("Summary at {}", metrics.time))?;
        for tal in &metrics.tals {
            line(format_args!("{}: ", tal.name()))?;
            line(format_args!(
                "            ROAs: {:7} verified;",
                tal.publication.valid_roas
            ))?;
            line(format_args!(
                "            VRPs: {:7} verified, {:7} final;",
                tal.payload.vrps().valid,
                tal.payload.vrps().contributed
            ))?;
            line(format_args!(
                "    router certs: {:7} verified;",
                tal.publication.valid_ee_certs,
            ))?;
            line(format_args!(
                "     router keys: {:7} verified, {:7} final.",
                tal.payload.router_keys.valid,
                tal.payload.router_keys.contributed
            ))?;
        }
        line(format_args!("total: "))?;
        line(format_args!(
            "            ROAs: {:7} verified;",
            metrics.publication.valid_roas
        ))?;
        line(format_args!(
            "            VRPs: {:7} verified, {:7} final;",
            metrics.payload.vrps().valid,
            metrics.payload.vrps().contributed
        ))?;
        line(format_args!(
            "    router certs: {:7} verified;",
            metrics.publication.valid_ee_certs,
        ))?;
        line(format_args!(
            "     router keys: {:7} verified, {:7} final.",
            metrics.payload.router_keys.valid,
            metrics.payload.router_keys.contributed
        ))
    }

    pub fn log(metrics: &Metrics) {
        Self::produce_header(metrics, |args| {
            info!("{}", args);
            Ok(())
        }).unwrap()
    }
}

impl<W: io::Write> Formatter<W> for Summary {
    fn header(
        &self, _snapshot: &PayloadSnapshot, metrics: &Metrics, target: &mut W
    ) -> Result<(), io::Error> {
        Self::produce_header(metrics, |args| {
            writeln!(target, "{}", args)
        })
    }

    fn origin(
        &self, _origin: RouteOrigin, _info: &PayloadInfo, _target: &mut W
    ) -> Result<(), io::Error> {
        Ok(())
    }
}



//------------ NoOutput-------------------------------------------------------

struct NoOutput;

impl<W: io::Write> Formatter<W> for NoOutput {
    fn origin(
        &self, _origin: RouteOrigin, _info: &PayloadInfo, _target: &mut W
    ) -> Result<(), io::Error> {
        Ok(())
    }
}


