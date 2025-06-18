//! Output of validated RPKI payload.

use std::{error, fmt, io};
use std::str::FromStr;
use std::sync::Arc;
use bytes::Bytes;
use chrono::Utc;
use chrono::format::{Item, Numeric, Pad};
use log::{error, info};
use rpki::resources::{Asn, Prefix};
use rpki::resources::addr::ParsePrefixError;
use rpki::rtr::payload::{Aspa, RouteOrigin, RouterKey};
use rpki::util::base64;
use crate::config::Config;
use crate::error::Failed;
use crate::http::ContentType;
use crate::payload::{
    PayloadInfo, PayloadSnapshot
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

    /// JSON format using the SLURM version 1 scheme.
    Slurm,

    /// JSON format using the SLURM version 2 scheme.
    Slurm2,

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
        ("slurm2", OutputFormat::Slurm2),
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
            OutputFormat::Slurm | OutputFormat::Slurm2
                => ContentType::JSON,
            _ => ContentType::TEXT,
        }
    }

    fn formatter<W: io::Write>(self) -> Box<dyn Formatter<W> + Send + Sync> {
        match self {
            OutputFormat::Csv => Box::new(Csv),
            OutputFormat::CompatCsv => Box::new(CompatCsv),
            OutputFormat::ExtendedCsv => Box::new(ExtendedCsv),
            OutputFormat::Json => Box::new(Json),
            OutputFormat::ExtendedJson => Box::new(ExtendedJson),
            OutputFormat::Slurm => Box::new(Slurm),
            OutputFormat::Slurm2 => Box::new(Slurm2),
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
    resources: Vec<SelectResource>,

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

    /// Add an origin ASN to select.
    pub fn push_asn(&mut self, asn: Asn) {
        self.resources.push(SelectResource::Asn(asn))
    }

    /// Add a origin prefix to select.
    pub fn push_prefix(&mut self, prefix: Prefix) {
        self.resources.push(SelectResource::Prefix(prefix))
    }

    /// Returns whether there are any resources.
    pub fn has_resources(&self) -> bool {
        !self.resources.is_empty()
    }

    /// Returns whether an origin should be included in output.
    pub fn include_origin(&self, origin: RouteOrigin) -> bool {
        for select in &self.resources {
            if select.include_origin(origin, self.more_specifics) {
                return true
            }
        }
        false
    }

    /// Returns whether a router key should be included in output.
    pub fn include_router_key(&self, key: &RouterKey) -> bool {
        for select in &self.resources {
            if select.include_router_key(key) {
                return true
            }
        }
        false
    }

    /// Returns whether an ASPA should be included in output.
    pub fn include_aspa(&self, aspa: &Aspa) -> bool {
        for select in &self.resources {
            if select.include_aspa(aspa) {
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


//------------ SelectResource ------------------------------------------------

/// A selection rule for origins.
#[derive(Clone, Copy, Debug)]
enum SelectResource {
    /// Include resources related to the given ASN.
    Asn(Asn),

    /// Include resources related to the given prefix.
    Prefix(Prefix),
}

impl SelectResource {
    /// Returns whether this rule selects payload.
    fn include_origin(
        self, origin: RouteOrigin, more_specifics: bool
    ) -> bool {
        match self {
            SelectResource::Asn(asn) => origin.asn == asn,
            SelectResource::Prefix(prefix) => {
                origin.prefix.prefix().covers(prefix)
                || (more_specifics && prefix.covers(origin.prefix.prefix()))
            }
        }
    }

    fn include_router_key(self, key: &RouterKey) -> bool {
        match self {
            SelectResource::Asn(asn) => key.asn == asn,
            _ => false
        }
    }

    fn include_aspa(self, aspa: &Aspa) -> bool {
        match self {
            SelectResource::Asn(asn) => aspa.customer == asn,
            _ => false,
        }
    }
}


//------------ Output --------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Output {
    /// Limiting data to be included.
    ///
    /// If this is `None`, all data is potentially included.
    selection: Option<Selection>,

    /// Should we include route origins?
    route_origins: bool,

    /// Should we include router keys?
    router_keys: bool,

    /// Should we include ASPA data?
    aspas: bool,
}

impl Output {
    /// Creates new default output
    pub fn new() -> Self {
        Self {
            selection: None,
            route_origins: true,
            router_keys: true,
            aspas: true
        }
    }

    /// Creates a new output based on the config.
    pub fn from_config(config: &Config) -> Self {
        let mut res = Self::new();
        res.update_from_config(config);
        res
    }

    pub fn from_query(query: Option<&str>) -> Result<Self, QueryError> {
        let mut res = Self::new();
        res.update_from_query(query)?;
        Ok(res)
    }

    pub fn update_from_config(&mut self, config: &Config) {
        if !config.enable_bgpsec {
            self.no_router_keys();
        }
        if !config.enable_aspa {
            self.no_aspas();
        }
    }

    /// Updates the output value from query parameters.
    pub fn update_from_query(
        &mut self, query: Option<&str>
    ) -> Result<(), QueryError> {
        let query = match query {
            Some(query) => query,
            None => return Ok(())
        };

        let mut selection = Selection::new();
        for (key, value) in form_urlencoded::parse(query.as_ref()) {
            if key == "select-prefix" || key == "filter-prefix" {
                selection.resources.push(
                    SelectResource::Prefix(Prefix::from_str(&value)?)
                );
            }
            else if key == "select-asn" || key == "filter-asn" {
                selection.resources.push(
                    SelectResource::Asn(
                        Asn::from_str(&value).map_err(|_| QueryError)?
                    )
                );
            }
            else if key == "include" {
                for value in value.split(',') {
                    #[allow(clippy::single_match)]
                    match value {
                        "more-specifics" => selection.more_specifics = true,
                        _ => { }
                    }
                }
            }
            else if key == "exclude" {
                for value in value.split(',') {
                    match value {
                        "routeOrigins" => self.route_origins = false,
                        "routerKeys" => self.router_keys = false,
                        "aspas" => self.aspas = false,
                        _ => { }
                    }
                }
            }
            else {
                return Err(QueryError)
            }
        }

        if selection.has_resources() {
            self.set_selection(selection)
        }

        Ok(())
    }

    pub fn set_selection(&mut self, selection: Selection) {
        self.selection = Some(selection)
    }

    pub fn no_route_origins(&mut self) {
        self.route_origins = false
    }

    pub fn no_router_keys(&mut self) {
        self.router_keys = false
    }

    pub fn no_aspas(&mut self) {
        self.aspas = false
    }

    /// Outputs the payload snapshot to the target in the given format.
    pub fn write<W: io::Write>(
        self,
        snapshot: Arc<PayloadSnapshot>,
        metrics: Arc<Metrics>,
        format: OutputFormat,
        target: &mut W,
    ) -> Result<(), io::Error> {
        let mut stream = OutputStream::new(self, snapshot, metrics, format);
        while stream.write_next(target)? { }
        Ok(())
    }

    /// Creates an output stream for the given format.
    pub fn stream(
        self,
        snapshot: Arc<PayloadSnapshot>,
        metrics: Arc<Metrics>,
        format: OutputFormat,
    ) -> impl Iterator<Item = Bytes> + Send + Sync + 'static {
        OutputStream::new(self, snapshot, metrics, format)
    }

    fn include_origin(&self, origin: RouteOrigin) -> bool {
        match self.selection.as_ref() {
            Some(selection) => selection.include_origin(origin),
            None => true
        }
    }

    fn include_router_key(&self, key: &RouterKey) -> bool {
        match self.selection.as_ref() {
            Some(selection) => selection.include_router_key(key),
            None => true
        }
    }

    fn include_aspa(&self, aspa: &Aspa) -> bool {
        match self.selection.as_ref() {
            Some(selection) => selection.include_aspa(aspa),
            None => true
        }
    }
}

impl Default for Output {
    fn default() -> Self {
        Self::new()
    }
}


//------------ OutputStream --------------------------------------------------

struct OutputStream<Target> {
    output: Output,
    snapshot: Arc<PayloadSnapshot>,
    metrics: Arc<Metrics>,
    state: StreamState,
    formatter: Box<dyn Formatter<Target> + Send + Sync>,
}

#[derive(Clone, Copy)]
enum StreamState {
    Header,
    OriginBefore,
    Origin,
    OriginAfter,
    KeyBefore,
    Key,
    KeyAfter,
    AspaBefore,
    Aspa,
    AspaAfter,
    Done
}

impl<Target: io::Write> OutputStream<Target> {
    /// Creates a new output stream.
    fn new(
        output: Output,
        snapshot: Arc<PayloadSnapshot>,
        metrics: Arc<Metrics>,
        format: OutputFormat,
    ) -> Self {
        OutputStream {
            output, snapshot, metrics,
            state: StreamState::Header,
            formatter: format.formatter(),
        }
    }

    /// Writes the next item to the target.
    ///
    /// Returns `Ok(true)` if something was written and there may be more
    /// data. Returns `Ok(false)` if nothing was written and there also is
    /// no more data.
    pub fn write_next(
        &mut self, target: &mut Target
    ) -> Result<bool, io::Error> {
        let next = match self.state {
            StreamState::Header => {
                self.formatter.header(
                    &self.snapshot, &self.metrics, target
                )?
            },
            StreamState::OriginBefore => {
                self.formatter.before_origins(target, self.output.route_origins)?
            },
            StreamState::Origin => {
                let mut iter = self.snapshot.clone().arc_origin_iter();
                let mut first = true;
                while let Some((origin, info)) = iter.next_with_info() {
                    if !self.output.include_origin(origin) {
                        continue
                    }
                    if first {
                        first = false;
                    }
                    else {
                        self.formatter.origin_delimiter(target)?;
                    }
                    self.formatter.origin(origin, info, target)?;
                }
                StreamState::OriginAfter
            },
            StreamState::OriginAfter => {
                self.formatter.after_origins(target)?
            },
            StreamState::KeyBefore => {
                self.formatter.before_router_keys(target, self.output.router_keys)?
            },
            StreamState::Key => {
                let mut iter = self.snapshot.clone().arc_router_key_iter();
                let mut first = true;
                while let Some((key, info)) = iter.next_with_info() {
                    if !self.output.include_router_key(key) {
                        continue
                    }
                    if first {
                        first = false;
                    }
                    else {
                        self.formatter.router_key_delimiter(target)?;
                    }
                    self.formatter.router_key(key, info, target)?;
                }
                StreamState::KeyAfter
            },
            StreamState::KeyAfter => {
                self.formatter.after_router_keys(target)?
            },
            StreamState::AspaBefore => {
                self.formatter.before_aspas(target, self.output.aspas)?
            },
            StreamState::Aspa => {
                let mut iter = self.snapshot.clone().arc_aspa_iter();
                let mut first = true;
                while let Some((aspa, info)) = iter.next_with_info() {
                    if !self.output.include_aspa(aspa) {
                        continue
                    }
                    if first {
                        first = false;
                    }
                    else {
                        self.formatter.aspa_delimiter(target)?;
                    }
                    self.formatter.aspa(aspa, info, target)?;
                }
                StreamState::AspaAfter
            },
            StreamState::AspaAfter => {
                self.formatter.after_aspas(target)?
            },
            StreamState::Done => return Ok(false),
        };

        if matches!(next, StreamState::Done) {
            self.formatter.footer(
                self.metrics.as_ref(), target
            )?;
        }
        self.state = next;
        Ok(true)
    }
}

impl Iterator for OutputStream<Vec<u8>> {
    type Item = Bytes;

    fn next(&mut self) -> Option<Self::Item> {
        let mut res = Vec::new();
        while self.write_next(&mut res).expect("write to vec failed") {
            if res.len() > 64000 {
                return Some(res.into())
            }
        }
        if res.is_empty() {
            None
        }
        else {
            Some(res.into())
        }
    }
}


//------------ QueryError ----------------------------------------------------

#[derive(Debug)]
pub struct QueryError;

impl From<ParsePrefixError> for QueryError {
    fn from(_: ParsePrefixError) -> Self {
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
    ) -> Result<StreamState, io::Error> {
        let _ = (snapshot, metrics, target);
        Ok(StreamState::OriginBefore)
    }

    fn before_origins(
        &self, _target: &mut W, _origins: bool
    ) -> Result<StreamState, io::Error> {
        Ok(StreamState::Origin)
    }

    fn origin(
        &self, origin: RouteOrigin, info: &PayloadInfo, target: &mut W
    ) -> Result<(), io::Error>;

    fn origin_delimiter(&self, target: &mut W) -> Result<(), io::Error> {
        let _ = target;
        Ok(())
    }

    fn after_origins(
        &self, _target: &mut W
    ) -> Result<StreamState, io::Error> {
        Ok(StreamState::KeyBefore)
    }

    fn before_router_keys(
        &self, _target: &mut W, _keys: bool
    ) -> Result<StreamState, io::Error> {
        Ok(StreamState::Key)
    }

    fn router_key(
        &self, _key: &RouterKey, _info: &PayloadInfo, _target: &mut W
    ) -> Result<(), io::Error> {
        Ok(())
    }

    fn router_key_delimiter(&self, target: &mut W) -> Result<(), io::Error> {
        let _ = target;
        Ok(())
    }

    fn after_router_keys(
        &self, _target: &mut W
    ) -> Result<StreamState, io::Error> {
        Ok(StreamState::AspaBefore)
    }

    fn before_aspas(
        &self, _target: &mut W, _aspas: bool
    ) -> Result<StreamState, io::Error> {
        Ok(StreamState::Aspa)
    }

    fn aspa(
        &self, _aspa: &Aspa, _info: &PayloadInfo, _target: &mut W
    ) -> Result<(), io::Error> {
        Ok(())
    }

    fn aspa_delimiter(&self, target: &mut W) -> Result<(), io::Error> {
        let _ = target;
        Ok(())
    }

    fn after_aspas(
        &self, _target: &mut W
    ) -> Result<StreamState, io::Error> {
        Ok(StreamState::Done)
    }

    fn footer(
        &self, metrics: &Metrics, target: &mut W
    ) -> Result<StreamState, io::Error> {
        let _ = (metrics, target);
        Ok(StreamState::Done)
    }
}


//------------ Csv -----------------------------------------------------------

struct Csv;

impl<W: io::Write> Formatter<W> for Csv {
    fn header(
        &self, _snapshot: &PayloadSnapshot, _metrics: &Metrics, target: &mut W
    ) -> Result<StreamState, io::Error> {
        writeln!(target, "ASN,IP Prefix,Max Length,Trust Anchor")?;
        Ok(StreamState::OriginBefore)
    }

    fn before_origins(
            &self, _target: &mut W, origins: bool
        ) -> Result<StreamState, io::Error> {
        match origins {
            true => Ok(StreamState::Origin),
            false => Ok(StreamState::OriginAfter)
        }
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
    ) -> Result<StreamState, io::Error> {
        writeln!(
            target, "\"ASN\",\"IP Prefix\",\"Max Length\",\"Trust Anchor\""
        )?;
        Ok(StreamState::OriginBefore)
    }

    fn before_origins(
            &self, _target: &mut W, origins: bool
        ) -> Result<StreamState, io::Error> {
        match origins {
            true => Ok(StreamState::Origin),
            false => Ok(StreamState::OriginAfter)
        }
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
    ) -> Result<StreamState, io::Error> {
        writeln!(target, "URI,ASN,IP Prefix,Max Length,Not Before,Not After")?;
        Ok(StreamState::OriginBefore)
    }

    fn before_origins(
            &self, _target: &mut W, origins: bool
        ) -> Result<StreamState, io::Error> {
        match origins {
            true => Ok(StreamState::Origin),
            false => Ok(StreamState::OriginAfter)
        }
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
    ) -> Result<StreamState, io::Error> {
        write!(target,
            "{{\
            \n  \"metadata\": {{\
            \n    \"generated\": {},\
            \n    \"generatedTime\": \"{}\"\
            \n  }}",
            metrics.time.timestamp(),
            format_iso_date(metrics.time)
        )?;
        Ok(StreamState::OriginBefore)
    }

    fn before_origins(
        &self, target: &mut W, origins: bool
    ) -> Result<StreamState, io::Error> {
        if origins {
            writeln!(target,
                ",\
                \n  \"roas\": ["
            )?;    
            Ok(StreamState::Origin)
        } else {
            Ok(StreamState::KeyBefore)
        }
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

    fn origin_delimiter(&self, target: &mut W) -> Result<(), io::Error> {
        writeln!(target, ",")
    }

    fn after_origins(&self, target: &mut W) -> Result<StreamState, io::Error> {
        write!(target, "\n  ]")?;
        Ok(StreamState::KeyBefore)
    }

    fn before_router_keys(&self, target: &mut W, keys: bool) -> Result<StreamState, io::Error> {
        if keys {
            writeln!(target, ",\n  \"routerKeys\": [")?;
            Ok(StreamState::Key)
        } else {
            Ok(StreamState::AspaBefore)
        }
    }

    fn router_key(
        &self, key: &RouterKey, info: &PayloadInfo, target: &mut W
    ) -> Result<(), io::Error> {
        write!(target,
            "    {{ \"asn\": \"{}\", \"SKI\": \"{}\", \
            \"routerPublicKey\": \"{}\", \"ta\": \"{}\" }}",
            key.asn,
            key.key_identifier,
            key.key_info,
            info.tal_name().unwrap_or("N/A"),
        )
    }

    fn router_key_delimiter(&self, target: &mut W) -> Result<(), io::Error> {
        writeln!(target, ",")
    }

    fn after_router_keys(&self, target: &mut W) -> Result<StreamState, io::Error> {
        write!(target, "\n  ]")?;
        Ok(StreamState::AspaBefore)
    }

    fn before_aspas(&self, target: &mut W, aspas: bool) -> Result<StreamState, io::Error> {
        if aspas {
            writeln!(target, ",\n  \"aspas\": [")?;
            Ok(StreamState::Aspa)
        } else {
            Ok(StreamState::Done)
        }
    }

    fn aspa(
        &self, aspa: &Aspa, info: &PayloadInfo, target: &mut W
    ) -> Result<(), io::Error> {
        write!(target,
            "    {{ \"customer\": \"{}\", \"providers\": [", aspa.customer
        )?;

        let mut first = true;
        for item in aspa.providers.iter() {
            if first {
                write!(target, "\"{}\"", item)?;
                first = false;
            }
            else {
                write!(target, ", \"{}\"", item)?;
            }
        }

        write!(
            target, "], \"ta\": \"{}\" }}", info.tal_name().unwrap_or("N/A")
        )
    }

    fn aspa_delimiter(&self, target: &mut W) -> Result<(), io::Error> {
        writeln!(target, ",")
    }

    fn after_aspas(&self, target: &mut W) -> Result<StreamState, io::Error> {
        write!(target, "\n  ]")?;
        Ok(StreamState::Done)
    }

    fn footer(
        &self, _metrics: &Metrics, target: &mut W
    ) -> Result<StreamState, io::Error> {
        writeln!(target, "\n}}")?;
        Ok(StreamState::Done)
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
                    \"notAfter\": \"{}\" }}, \
                    \"stale\": \"{}\" \
                    }}",
                    json_str(roa.tal.name()),
                    format_iso_date(roa.roa_validity.not_before().into()),
                    format_iso_date(roa.roa_validity.not_after().into()),
                    format_iso_date(roa.chain_validity.not_before().into()),
                    format_iso_date(roa.chain_validity.not_after().into()),
                    format_iso_date(roa.point_stale.into()),
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
    ) -> Result<StreamState, io::Error> {
        write!(target,
            "{{\
            \n  \"metadata\": {{\
            \n    \"generated\": {},\
            \n    \"generatedTime\": \"{}\"\
            \n  }}",
            metrics.time.timestamp(),
            format_iso_date(metrics.time)
        )?;
        Ok(StreamState::OriginBefore)
    }

    fn before_origins(
        &self, target: &mut W, origins: bool
    ) -> Result<StreamState, io::Error> {
        if origins {
            writeln!(target,
                ",\
                \n  \"roas\": ["
            )?;    
            Ok(StreamState::Origin)
        } else {
            Ok(StreamState::KeyBefore)
        }
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

    fn origin_delimiter(&self, target: &mut W) -> Result<(), io::Error> {
        writeln!(target, ",")
    }

    fn after_origins(&self, target: &mut W) -> Result<StreamState, io::Error> {
        write!(target, "\n  ]")?;
        Ok(StreamState::KeyBefore)
    }

    fn before_router_keys(&self, target: &mut W, keys: bool) -> Result<StreamState, io::Error> {
        if keys {
            writeln!(target, ",\n  \"routerKeys\": [")?;
            Ok(StreamState::Key)
        } else {
            Ok(StreamState::AspaBefore)
        }
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

    fn router_key_delimiter(&self, target: &mut W) -> Result<(), io::Error> {
        writeln!(target, ",")
    }

    fn after_router_keys(&self, target: &mut W) -> Result<StreamState, io::Error> {
        write!(target, "\n  ]")?;
        Ok(StreamState::AspaBefore)
    }

    fn before_aspas(&self, target: &mut W, aspas: bool) -> Result<StreamState, io::Error> {
        if aspas {
            writeln!(target, ",\n  \"aspas\": [")?;
            Ok(StreamState::Aspa)
        } else {
            Ok(StreamState::Done)
        }
    }

    fn aspa(
        &self, aspa: &Aspa, info: &PayloadInfo, target: &mut W
    ) -> Result<(), io::Error> {
        write!(target,
            "    {{ \"customer\": \"{}\", \"providers\": [", aspa.customer
        )?;

        let mut first = true;
        for item in aspa.providers.iter() {
            if first {
                write!(target, "\"{}\"", item)?;
                first = false;
            }
            else {
                write!(target, ", \"{}\"", item)?;
            }
        }

        write!(target, "], \"source\": [")?;
        Self::payload_info(info, "aspa", target)?;
        write!(target, "] }}")
    }

    fn aspa_delimiter(&self, target: &mut W) -> Result<(), io::Error> {
        writeln!(target, ",")
    }

    fn after_aspas(&self, target: &mut W) -> Result<StreamState, io::Error> {
        write!(target, "\n  ]")?;
        Ok(StreamState::Done)
    }

    fn footer(
        &self, _metrics: &Metrics, target: &mut W
    ) -> Result<StreamState, io::Error> {
        writeln!(target, "\n}}")?;
        Ok(StreamState::Done)
    }
}


//------------ Slurm ---------------------------------------------------------

struct Slurm;

impl<W: io::Write> Formatter<W> for Slurm {
    fn header(
        &self, _snapshot: &PayloadSnapshot, _metrics: &Metrics, target: &mut W
    ) -> Result<StreamState, io::Error> {
        writeln!(target,
            "{{\
            \n  \"slurmVersion\": 1,\
            \n  \"validationOutputFilters\": {{\
            \n    \"prefixFilters\": [ ],\
            \n    \"bgpsecFilters\": [ ]\
            \n  }},\
            \n  \"locallyAddedAssertions\": {{"
        )?;
        Ok(StreamState::OriginBefore)
    }

    fn before_origins(
            &self, target: &mut W, origins: bool
        ) -> Result<StreamState, io::Error> {
        writeln!(target, "    \"prefixAssertions\": [")?;
        match origins {
            true => Ok(StreamState::Origin),
            false => Ok(StreamState::OriginAfter)
        }
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

    fn after_origins(&self, target: &mut W) -> Result<StreamState, io::Error> {
        writeln!(target,
            "\n    ],"
        )?;
        Ok(StreamState::KeyBefore)
    }

    fn before_router_keys(
            &self, target: &mut W, keys: bool
        ) -> Result<StreamState, io::Error> {
        writeln!(target, 
        "    \"bgpsecAssertions\": [")?;
        match keys {
            true => Ok(StreamState::Key),
            false => Ok(StreamState::KeyAfter)
        }
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
        base64::Slurm.write_encoded_slice(
            key.key_identifier.as_slice(),
            target,
        )?;
        write!(target, "\",\
            \n        \"routerPublicKey\": \""
        )?;
        base64::Slurm.write_encoded_slice(key.key_info.as_slice(), target)?;
        write!(target, "\",\
            \n        \"comment\": \"{}\"\
            \n      }}",
            info.tal_name().unwrap_or("N/A")
        )
    }

    fn after_router_keys(
            &self, target: &mut W
        ) -> Result<StreamState, io::Error> {
        writeln!(target, "\n    ]")?;
        Ok(StreamState::Done)
    }

    fn footer(
        &self, _metrics: &Metrics, target: &mut W
    ) -> Result<StreamState, io::Error> {
        writeln!(target,
           "  }}\
            \n}}"
        )?;
        Ok(StreamState::Done)
    }

    fn origin_delimiter(&self, target: &mut W) -> Result<(), io::Error> {
        writeln!(target, ",")
    }

    fn router_key_delimiter(&self, target: &mut W) -> Result<(), io::Error> {
        writeln!(target, ",")
    }
}


//------------ Slurm2 --------------------------------------------------------

struct Slurm2;

impl<W: io::Write> Formatter<W> for Slurm2 {
    fn header(
        &self, _snapshot: &PayloadSnapshot, _metrics: &Metrics, target: &mut W
    ) -> Result<StreamState, io::Error> {
        writeln!(target,
            "{{\
            \n  \"slurmVersion\": 2,\
            \n  \"validationOutputFilters\": {{\
            \n    \"prefixFilters\": [ ],\
            \n    \"bgpsecFilters\": [ ],\
            \n    \"aspaFilters\": [ ]\
            \n  }},\
            \n  \"locallyAddedAssertions\": {{"
        )?;
        Ok(StreamState::OriginBefore)
    }

    fn before_origins(
            &self, target: &mut W, origins: bool
        ) -> Result<StreamState, io::Error> {
        writeln!(target, "    \"prefixAssertions\": [")?;
        match origins {
            true => Ok(StreamState::Origin),
            false => Ok(StreamState::OriginAfter)
        }
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

    fn after_origins(&self, target: &mut W) -> Result<StreamState, io::Error> {
        writeln!(target,
            "\n    ],"
        )?;
        Ok(StreamState::KeyBefore)
    }

    fn before_router_keys(
            &self, target: &mut W, keys: bool
        ) -> Result<StreamState, io::Error> {
        writeln!(target, 
        "    \"bgpsecAssertions\": [")?;
        match keys {
            true => Ok(StreamState::Key),
            false => Ok(StreamState::KeyAfter)
        }
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
        base64::Slurm.write_encoded_slice(
            key.key_identifier.as_slice(),
            target,
        )?;
        write!(target, "\",\
            \n        \"routerPublicKey\": \""
        )?;
        base64::Slurm.write_encoded_slice(key.key_info.as_slice(), target)?;
        write!(target, "\",\
            \n        \"comment\": \"{}\"\
            \n      }}",
            info.tal_name().unwrap_or("N/A")
        )
    }

    fn after_router_keys(
            &self, target: &mut W
        ) -> Result<StreamState, io::Error> {
        writeln!(target, "\n    ],")?;
        Ok(StreamState::AspaBefore)
    }

    fn before_aspas(&self, target: &mut W, aspas: bool) -> Result<StreamState, io::Error> {
        writeln!(target, "    \"aspaAssertions\": [")?;
        match aspas {
            true => Ok(StreamState::Aspa),
            false => Ok(StreamState::AspaAfter)
        }
    }

    fn aspa(
        &self, aspa: &Aspa, info: &PayloadInfo, target: &mut W
    ) -> Result<(), io::Error> {
        write!(target,
            "      {{ \
            \n        \"customerAsn\": {}, \
            \n        \"providerAsns\": [", aspa.customer.into_u32()
        )?;

        let mut first = true;
        for item in aspa.providers.iter() {
            if first {
                write!(target, "\n          {}", item.into_u32())?;
                first = false;
            }
            else {
                write!(target, ", \n          {}", item.into_u32())?;
            }
        }
        write!(target,
            "\n        ],\
            \n        \"comment\": \"{}\"\
            \n      }}", info.tal_name().unwrap_or("N/A"))
    }

    fn after_aspas(
            &self, target: &mut W
        ) -> Result<StreamState, io::Error> {
        writeln!(target, "\n    ]")?;
        Ok(StreamState::Done)
    }

    fn aspa_delimiter(&self, target: &mut W) -> Result<(), io::Error> {
        writeln!(target, ",")
    }

    fn footer(
        &self, _metrics: &Metrics, target: &mut W
    ) -> Result<StreamState, io::Error> {
        writeln!(target,
           "  }}\
            \n}}"
        )?;
        Ok(StreamState::Done)
    }

    fn origin_delimiter(&self, target: &mut W) -> Result<(), io::Error> {
        writeln!(target, ",")
    }

    fn router_key_delimiter(&self, target: &mut W) -> Result<(), io::Error> {
        writeln!(target, ",")
    }
}

//------------ Openbgpd ------------------------------------------------------

struct Openbgpd;

impl<W: io::Write> Formatter<W> for Openbgpd {
    fn header(
        &self, _snapshot: &PayloadSnapshot, _metrics: &Metrics, target: &mut W
    ) -> Result<StreamState, io::Error> {
        writeln!(target, "roa-set {{")?;
        Ok(StreamState::OriginBefore)
    }

    fn footer(
        &self, _metrics: &Metrics, target: &mut W
    ) -> Result<StreamState, io::Error> {
        writeln!(target, "}}")?;
        Ok(StreamState::Done)
    }

    fn before_origins(
            &self, _target: &mut W, origins: bool
        ) -> Result<StreamState, io::Error> {
        match origins {
            true => Ok(StreamState::Origin),
            false => Ok(StreamState::OriginAfter)
        }
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
    fn before_origins(
            &self, _target: &mut W, origins: bool
        ) -> Result<StreamState, io::Error> {
        match origins {
            true => Ok(StreamState::Origin),
            false => Ok(StreamState::OriginAfter)
        }
    }

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
    fn before_origins(
            &self, _target: &mut W, origins: bool
        ) -> Result<StreamState, io::Error> {
        match origins {
            true => Ok(StreamState::Origin),
            false => Ok(StreamState::OriginAfter)
        }
    }

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
    fn before_origins(
            &self, _target: &mut W, origins: bool
        ) -> Result<StreamState, io::Error> {
        match origins {
            true => Ok(StreamState::Origin),
            false => Ok(StreamState::OriginAfter)
        }
    }

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
                tal.publication.valid_router_certs,
            ))?;
            line(format_args!(
                "     router keys: {:7} verified, {:7} final;",
                tal.payload.router_keys.valid,
                tal.payload.router_keys.contributed
            ))?;
            line(format_args!(
                "           ASPAs: {:7} verified, {:7} final;",
                tal.publication.valid_aspas,
                tal.payload.aspas.contributed
            ))?;
        }
        line(format_args!("total: "))?;
        line(format_args!(
            "            ROAs: {:7} verified;",
            metrics.publication.valid_roas
        ))?;
        line(format_args!(
            "            VRPs: {:7} verified, {:7} final;",
            metrics.snapshot.payload.vrps().valid,
            metrics.snapshot.payload.vrps().contributed
        ))?;
        line(format_args!(
            "    router certs: {:7} verified;",
            metrics.publication.valid_router_certs,
        ))?;
        line(format_args!(
            "     router keys: {:7} verified, {:7} final;",
            metrics.snapshot.payload.router_keys.valid,
            metrics.snapshot.payload.router_keys.contributed
        ))?;
        line(format_args!(
            "           ASPAs: {:7} verified, {:7} final;",
            metrics.publication.valid_aspas,
            metrics.snapshot.payload.aspas.contributed
        ))?;
        Ok(())
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
    ) -> Result<StreamState, io::Error> {
        Self::produce_header(metrics, |args| {
            writeln!(target, "{}", args)
        })?;
        Ok(StreamState::Done)
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


//============ Tests =========================================================

#[cfg(test)]
mod test {
    use chrono::DateTime;
    use rpki::{crypto::KeyIdentifier, repository::x509::Time, resources::MaxLenPrefix, rtr::pdu::{ProviderAsns, RouterKeyInfo}};
    #[allow(unused_imports)]
    use std::{fs::{self}, io::BufWriter, path::PathBuf, io::Write};

    use crate::slurm::ExceptionInfo;

    use super::*;

    #[test]
    fn outputs() {
        for format in OutputFormat::VALUES { 
            if matches!(format.1, OutputFormat::Rpsl) {
                // RPSL includes the current time, making unit tests impossible
                continue;
            }
            for variation in [
                (true, true, true),
                (true, true, false),
                (true, false, true),
                (true, false, false),
                (false, true, true),
                (false, true, false),
                (false, false, true),
                (false, false, false),
            ] {
                let output_format = format.1;

                let mut output = Output::new();

                let payload_info = ExceptionInfo {
                    path: None,
                    comment: None
                };
                let payload_info: Arc<ExceptionInfo> = Arc::new(payload_info);

                let mut origins: Vec<(RouteOrigin, PayloadInfo)> = vec![];
                {
                    let ro = RouteOrigin::new(
                        MaxLenPrefix::from_str("12.34.56.0/24").unwrap(), 
                        Asn::from_u32(1234)
                    );
                    origins.push((ro, payload_info.clone().into()));
                    origins.push((ro, payload_info.clone().into()));
                }

                let mut router_keys: Vec<(RouterKey, PayloadInfo)> = vec![];
                {
                    let key_info = 
                    RouterKeyInfo::try_from(vec![0u8; 64]).unwrap();
                    let key_identifier = KeyIdentifier::from([0u8; 20]);
                    let rk = RouterKey::new(
                        key_identifier, 
                        Asn::from_u32(1234), 
                        key_info
                    );
                    router_keys.push((rk.clone(), payload_info.clone().into()));
                    router_keys.push((rk.clone(), payload_info.clone().into()));
                }

                let mut aspas: Vec<(Aspa, PayloadInfo)> = vec![];
                {
                    let providers = ProviderAsns::try_from_iter(
                        [1, 2, 3, 4].iter()
                        .map(|x| Asn::from_u32(*x))).unwrap();
                    let aspa = Aspa::new(
                        Asn::from_u32(1234),
                        providers
                    );
                    aspas.push((aspa.clone(), payload_info.clone().into()));
                    aspas.push((aspa.clone(), payload_info.clone().into()));
                }

                let datetime = DateTime::from_timestamp(0, 0).unwrap();
                let snapshot = PayloadSnapshot::new(
                    origins.into_iter(),
                    router_keys.into_iter(),
                    aspas.into_iter(),
                    Some(Time::new(datetime))
                );
                let snapshot = Arc::new(snapshot);

                let metrics = Metrics {
                    time: datetime,
                    rsync: Vec::new(),
                    rrdp: Vec::new(),
                    tals: Vec::new(),
                    repositories: Vec::new(),
                    publication: Default::default(),
                    local: Default::default(),
                    snapshot: Default::default(),
                };
                let metrics = Arc::new(metrics);

                if !variation.0 {
                    output.no_route_origins();
                }
                if !variation.1 {
                    output.no_router_keys();
                }
                if !variation.2 {
                    output.no_aspas();
                }

                let mut buf = BufWriter::new(Vec::new());

                output.write(snapshot, metrics, output_format,  &mut buf).unwrap();

                let bytes = buf.into_inner().unwrap();
                let string = String::from_utf8(bytes).unwrap();

                let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
                d.push("test/output");
                d.push(format!("{}{}{}.{}", 
                    variation.0 as u32, 
                    variation.1 as u32, 
                    variation.2 as u32, 
                    format.0
                ));

                println!("{} {:#?}", format.0, variation);
                // git automatically changes \n to \r\n on Windows (and back 
                // again when committing). This breaks the test.
                let file = fs::read_to_string(d).unwrap().replace("\r\n", "\n");
                assert_eq!(string, file);

                // Code to write the presumed correct output to the folder:
                // let mut file = fs::File::create(d).unwrap();
                // file.write_all(string.as_bytes()).unwrap();
            }
        }
    }
}
