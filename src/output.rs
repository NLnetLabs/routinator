//! Output of validated RPKI payload.

#![allow(unused)] // XXX TODO

use std::{error, fmt, io, mem};
use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use bytes::Bytes;
use chrono::Utc;
use chrono::format::{Item, Numeric, Pad};
use log::{error, info};
use rpki::resources::{Asn, Prefix};
use rpki::resources::addr::ParsePrefixError;
use rpki::rtr::payload::{Aspa, RouteOrigin, RouterKey};
use rpki::util::base64;
use tokio::sync::mpsc;
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
}


//--- FromStr

impl FromStr for OutputFormat {
    type Err = Failed;

    fn from_str(value: &str) -> Result<Self, Failed> {
        Self::try_from_str(value).ok_or_else(|| {
            error!("Unknown output format: {value}");
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

impl Default for Output {
    fn default() -> Self {
        Self::new()
    }
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
        let mut fut = self._write(&snapshot, &metrics, format, target);
        let fut = unsafe { Pin::new_unchecked(&mut fut) };
        match fut.poll(&mut Context::from_waker(Waker::noop())) {
            Poll::Pending => panic!("incomplete write"),
            Poll::Ready(res) => res,
        }
    }

    pub async fn write_frames(
        self,
        snapshot: Arc<PayloadSnapshot>,
        metrics: Arc<Metrics>,
        format: OutputFormat,
        mut target: FrameWriter,
    ) -> Result<(), io::Error> {
        self._write(&snapshot, &metrics, format, &mut target).await?;
        target.flush().await
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

    fn origins<'s>(
        &'s self, payload: &'s PayloadSnapshot
    ) -> impl Iterator<Item = (RouteOrigin, &'s PayloadInfo)> + 's {
        payload.origins().filter(|(origin, _)| self.include_origin(*origin))
    }

    fn router_keys<'s>(
        &'s self, payload: &'s PayloadSnapshot
    ) -> impl Iterator<Item = (&'s RouterKey, &'s PayloadInfo)> + 's {
        payload.router_keys().filter(|(key, _)| self.include_router_key(key))
    }

    fn aspas<'s>(
        &'s self, payload: &'s PayloadSnapshot
    ) -> impl Iterator<Item = (&'s Aspa, &'s PayloadInfo)> + 's {
        payload.aspas().filter(|(aspa, _)| self.include_aspa(aspa))
    }
}


impl Output {
    async fn _write(
        self,
        snapshot: &PayloadSnapshot,
        metrics: &Metrics,
        format: OutputFormat,
        target: &mut impl WriteOutput,
    ) -> Result<(), io::Error> {
        use self::OutputFormat::*;

        match format {
            Csv => self.csv(snapshot, target).await,
            CompatCsv => self.compat_csv(snapshot, target).await,
            ExtendedCsv => self.extended_csv(snapshot, target).await,
            Json => self.json(snapshot, metrics, target).await,
            ExtendedJson => {
                self.extended_json(snapshot, metrics, target).await
            }
            Slurm => self.slurm(snapshot, target).await,
            Slurm2 => self.slurm2(snapshot, target).await,
            Openbgpd => self.openbgpd(snapshot, target).await,
            Bird1 => self.bird1(snapshot, target).await,
            Bird2 => self.bird2(snapshot, target).await,
            Rpsl => self.rpsl(snapshot, target).await,
            Summary => self.summary(metrics, target),
            None => Ok(()),
        }
    }

    async fn csv(
        self, snapshot: &PayloadSnapshot, mut target: &mut impl WriteOutput,
    ) -> Result<(), io::Error> {
        writeln!(target, "ASN,IP Prefix,Max Length,Trust Anchor")?;
        if self.route_origins {
            for (origin, info) in self.origins(snapshot) {
                writeln!(target, "{},{}/{},{},{}",
                    origin.asn,
                    origin.prefix.addr(), origin.prefix.prefix_len(),
                    origin.prefix.resolved_max_len(),
                    info.tal_name().unwrap_or("N/A"),
                )?;
                target.flush().await?;
            }
        }
        Ok(())
    }

    async fn compat_csv(
        self, snapshot: &PayloadSnapshot, mut target: &mut impl WriteOutput,
    ) -> Result<(), io::Error> {
        writeln!(
            target, "\"ASN\",\"IP Prefix\",\"Max Length\",\"Trust Anchor\""
        )?;
        if self.route_origins {
            for (origin, info) in self.origins(snapshot) {
                writeln!(target, "\"{}\",\"{}/{}\",\"{}\",\"{}\"",
                    origin.asn,
                    origin.prefix.addr(), origin.prefix.prefix_len(),
                    origin.prefix.resolved_max_len(),
                    info.tal_name().unwrap_or("N/A"),
                )?;
                target.flush().await?;
            }
        }
        Ok(())
    }

    async fn extended_csv(
        self, snapshot: &PayloadSnapshot, mut target: &mut impl WriteOutput,
    ) -> Result<(), io::Error> {
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

        writeln!(target,
            "URI,ASN,IP Prefix,Max Length,Not Before,Not After"
        )?;
        if self.route_origins {
            for (origin, info) in self.origins(snapshot) {
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
                                TIME_ITEMS.iter().cloned()
                            ),
                            validity.not_after().format_with_items(
                                TIME_ITEMS.iter().cloned()
                            )
                        )?
                    }
                    None => writeln!(target, "N/A,N/A")?,
                }
                target.flush().await?;
            }
        }
        Ok(())
    }

    async fn json(
        self, snapshot: &PayloadSnapshot, metrics: &Metrics,
        mut target: &mut impl WriteOutput,
    ) -> Result<(), io::Error> {
        // Header
        write!(target,
            "{{\
            \n  \"metadata\": {{\
            \n    \"generated\": {},\
            \n    \"generatedTime\": \"{}\"\
            \n  }}",
            metrics.time.timestamp(),
            format_iso_date(metrics.time)
        )?;

        // Origins
        if self.route_origins {
            let mut first = true;
            for (origin, info) in self.origins(snapshot) {
                if first {
                    first = false;
                    writeln!(target,
                        ",\
                        \n  \"roas\": ["
                    )?;    
                }
                else {
                    writeln!(target, ",")?
                }

                write!(target,
                    "    {{ \"asn\": \"{}\", \"prefix\": \"{}/{}\", \
                    \"maxLength\": {}, \"ta\": \"{}\" }}",
                    origin.asn,
                    origin.prefix.addr(), origin.prefix.prefix_len(),
                    origin.prefix.resolved_max_len(),
                    info.tal_name().unwrap_or("N/A"),
                )?;
                target.flush().await?;
            }
            if !first {
                write!(target, "\n  ]")?;
            }
        }

        // Router keys
        //
        if self.router_keys {
            let mut first = true;
            for (key, info) in self.router_keys(snapshot) {
                if first {
                    first = false;
                    writeln!(target,
                        ",\
                        \n  \"routerKeys\": ["
                    )?;    
                }
                else {
                    writeln!(target, ",")?
                }

                write!(target,
                    "    {{ \"asn\": \"{}\", \"SKI\": \"{}\", \
                    \"routerPublicKey\": \"{}\", \"ta\": \"{}\" }}",
                    key.asn,
                    key.key_identifier,
                    key.key_info,
                    info.tal_name().unwrap_or("N/A"),
                )?;
                target.flush().await?;
            }
            if !first {
                write!(target, "\n  ]")?;
            }
        }

        // ASPAs
        if self.aspas {
            let mut first = true;
            for (aspa, info) in self.aspas(snapshot) {
                if first {
                    first = false;
                    writeln!(target,
                        ",\
                        \n  \"aspas\": ["
                    )?;    
                }
                else {
                    writeln!(target, ",")?
                }

                write!(target,
                    "    {{ \"customer\": \"{}\", \"providers\": [",
                    aspa.customer
                )?;

                let mut first_provider = true;
                for item in aspa.providers.iter() {
                    if first_provider {
                        write!(target, "\"{item}\"")?;
                        first_provider = false;
                    }
                    else {
                        write!(target, ", \"{item}\"")?;
                    }
                }

                write!(
                    target,
                    "], \"ta\": \"{}\" }}", info.tal_name().unwrap_or("N/A")
                )?;
                target.flush().await?;
            }
            if !first {
                write!(target, "\n  ]")?;
            }
        }

        writeln!(target, "\n}}")
    }

    async fn extended_json(
        self, snapshot: &PayloadSnapshot, metrics: &Metrics,
        mut target: &mut impl WriteOutput,
    ) -> Result<(), io::Error> {
        // Header
        write!(target,
            "{{\
            \n  \"metadata\": {{\
            \n    \"generated\": {},\
            \n    \"generatedTime\": \"{}\"\
            \n  }}",
            metrics.time.timestamp(),
            format_iso_date(metrics.time)
        )?;

        // Route origins
        if self.route_origins {
            let mut first = true;
            for (origin, info) in self.origins(snapshot) {
                if first {
                    first = false;
                    writeln!(target,
                        ",\
                        \n  \"roas\": ["
                    )?;    
                }
                else {
                    writeln!(target, ",")?;
                }

                write!(target,
                    "    {{ \"asn\": \"{}\", \"prefix\": \"{}/{}\", \
                    \"maxLength\": {}, \"source\": [",
                    origin.asn,
                    origin.prefix.addr(), origin.prefix.prefix_len(),
                    origin.prefix.resolved_max_len(),
                )?;
                Self::extended_json_payload_info(info, "roa", target)?;
                write!(target, "] }}")?;
                target.flush().await?;
            }
            if !first {
                write!(target, "\n  ]")?;
            }
        }

        // Router keys
        if self.router_keys {
            let mut first = true;
            for (key, info) in self.router_keys(snapshot) {
                if first {
                    first = false;
                    writeln!(target, ",\n  \"routerKeys\": [")?;
                }
                else {
                    writeln!(target, ",")?;
                }

                write!(target,
                    "    {{ \"asn\": \"{}\", \"SKI\": \"{}\", \
                    \"routerPublicKey\": \"{}\", \"source\": [",
                    key.asn,
                    key.key_identifier,
                    key.key_info,
                )?;
                Self::extended_json_payload_info(info, "cer", target)?;
                write!(target, "] }}")?;
                target.flush().await?;
            }
            if !first {
                write!(target, "\n  ]")?;
            }
        }

        // ASPAs
        if self.aspas {
            let mut first = true;
            for (aspa, info) in self.aspas(snapshot) {
                if first {
                    first = false;
                    writeln!(target, ",\n  \"aspas\": [")?;
                }
                else {
                    writeln!(target, ",")?;
                }

                write!(target,
                    "    {{ \"customer\": \"{}\", \"providers\": [",
                    aspa.customer
                )?;

                let mut first_provider = true;
                for item in aspa.providers.iter() {
                    if first_provider {
                        write!(target, "\"{item}\"")?;
                        first_provider = false;
                    }
                    else {
                        write!(target, ", \"{item}\"")?;
                    }
                }

                write!(target, "], \"source\": [")?;
                Self::extended_json_payload_info(info, "aspa", target)?;
                write!(target, "] }}")?;
                target.flush().await?;
            }
            if !first {
                write!(target, "\n  ]")?;
            }
        }

        writeln!(target, "\n}}")
    }

    fn extended_json_payload_info(
        info: &PayloadInfo, rpki_type: &str, target: &mut impl WriteOutput,
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
                    " {{ \"type\": \"{rpki_type}\", \"uri\": ",
                )?;
                match roa.uri.as_ref() {
                    Some(uri) => write!(target, "\"{uri}\"")?,
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

    async fn slurm(
        self, snapshot: &PayloadSnapshot, mut target: &mut impl WriteOutput,
    ) -> Result<(), io::Error> {
        writeln!(target,
            "{{\
            \n  \"slurmVersion\": 1,\
            \n  \"validationOutputFilters\": {{\
            \n    \"prefixFilters\": [ ],\
            \n    \"bgpsecFilters\": [ ]\
            \n  }},\
            \n  \"locallyAddedAssertions\": {{"
        )?;

        self.slurm_base(snapshot, target).await?;
        writeln!(target, "\n    ]")?;

        writeln!(target,
           "  }}\
            \n}}"
        )
    }

    async fn slurm_base(
        &self, snapshot: &PayloadSnapshot, target: &mut impl WriteOutput,
    ) -> Result<(), io::Error> {
        writeln!(target, "    \"prefixAssertions\": [")?;
        if self.route_origins {
            let mut first = true;
            for (origin, info) in self.origins(snapshot) {
                if first {
                    first = false;
                }
                else {
                    writeln!(target, ",")?;
                }

                writeln!(target,
                    "      {{\
                    \n        \"asn\": {},\
                    \n        \"prefix\": \"{}/{}\",",
                    origin.asn.into_u32(),
                    origin.prefix.addr(), origin.prefix.prefix_len()
                )?;
                if let Some(max_len) = origin.prefix.max_len() {
                    writeln!(
                        target, "        \"maxPrefixLength\": {max_len},"
                    )?;
                }
                write!(target,
                    "        \"comment\": \"{}\"\
                    \n      }}",
                    info.tal_name().unwrap_or("N/A")
                )?;
                target.flush().await?;
            }
        }
        writeln!(target,
            "\n    ],"
        )?;

        writeln!(target, "    \"bgpsecAssertions\": [")?;
        if self.router_keys {
            let mut first = true;
            for (key, info) in self.router_keys(snapshot) {
                if first {
                    first = false;
                }
                else {
                    writeln!(target, ",")?;
                }

                write!(target,
                     "      {{\
                    \n        \"asn\": {},\
                    \n        \"SKI\": \"{}\",\
                    \n        \"routerPublicKey\": \"{}\",\
                    \n        \"comment\": \"{}\"\
                    \n      }}",
                    key.asn.into_u32(),
                    base64::Slurm.display(key.key_identifier.as_slice()),
                    base64::Slurm.display(key.key_info.as_slice()),
                    info.tal_name().unwrap_or("N/A")
                )?;
                target.flush().await?;
            }
        }
        Ok(())
    }

    async fn slurm2(
        self, snapshot: &PayloadSnapshot, mut target: &mut impl WriteOutput,
    ) -> Result<(), io::Error> {
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

        self.slurm_base(snapshot, target).await?;
        writeln!(target, "\n    ],")?;

        writeln!(target, "    \"aspaAssertions\": [")?;
        if self.aspas {
            let mut first = true;
            for (aspa, info) in self.aspas(snapshot) {
                if first {
                    first = false;
                }
                else {
                    writeln!(target, ",")?;
                }

                write!(target,
                    "      {{ \
                    \n        \"customerAsn\": {}, \
                    \n        \"providerAsns\": [", aspa.customer.into_u32()
                )?;

                let mut first_provider = true;
                for item in aspa.providers.iter() {
                    if first_provider {
                        write!(target, "\n          {}", item.into_u32())?;
                        first_provider = false;
                    }
                    else {
                        write!(target, ", \n          {}", item.into_u32())?;
                    }
                }
                write!(target,
                    "\n        ],\
                    \n        \"comment\": \"{}\"\
                    \n      }}", info.tal_name().unwrap_or("N/A"))?;
                target.flush().await?;
            }
        }
        writeln!(target, "\n    ]")?;

        writeln!(target,
           "  }}\
            \n}}"
        )
    }

    async fn openbgpd(
        self, snapshot: &PayloadSnapshot, mut target: &mut impl WriteOutput,
    ) -> Result<(), io::Error> {
        writeln!(target, "roa-set {{")?;
        if self.route_origins {
            for (origin, _) in self.origins(snapshot) {
                write!(
                    target, "    {}/{}",
                    origin.prefix.addr(), origin.prefix.prefix_len(),
                )?;
                let max_len = origin.prefix.resolved_max_len();
                if origin.prefix.prefix_len() < max_len {
                    write!(target, " maxlen {max_len}")?;
                }
                writeln!(target, " source-as {}", u32::from(origin.asn))?;
                target.flush().await?;
            }
        }
        writeln!(target, "}}")
    }

    async fn bird1(
        self, snapshot: &PayloadSnapshot, mut target: &mut impl WriteOutput,
    ) -> Result<(), io::Error> {
        if self.route_origins {
            for (origin, _) in self.origins(snapshot) {
                writeln!(target, "roa {}/{} max {} as {};",
                    origin.prefix.addr(), origin.prefix.prefix_len(),
                    origin.prefix.resolved_max_len(),
                    u32::from(origin.asn)
                )?;
                target.flush().await?;
            }
        }
        Ok(())
    }

    async fn bird2(
        self, snapshot: &PayloadSnapshot, mut target: &mut impl WriteOutput,
    ) -> Result<(), io::Error> {
        if self.route_origins {
            for (origin, _) in self.origins(snapshot) {
                writeln!(target, "route {}/{} max {} as {};",
                    origin.prefix.addr(), origin.prefix.prefix_len(),
                    origin.prefix.resolved_max_len(),
                    u32::from(origin.asn)
                )?;
                target.flush().await?;
            }
        }
        Ok(())
    }

    async fn rpsl(
        self, snapshot: &PayloadSnapshot, mut target: &mut impl WriteOutput,
    ) -> Result<(), io::Error> {
        const TIME_ITEMS: &[Item<'static>] = &[
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

        if self.route_origins {
            for (origin, info) in self.origins(snapshot) {
                let now = Utc::now().format_with_items(
                    TIME_ITEMS.iter().cloned()
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
                )?;
                target.flush().await?;
            }
        }
        Ok(())
    }

    fn summary(
        self, metrics: &Metrics, mut target: &mut impl WriteOutput,
    ) -> Result<(), io::Error> {
        metrics.produce_summary(move |args| {
            writeln!(&mut target, "{args}")
        })
    }

}


//------------ WriteOutput ---------------------------------------------------

trait WriteOutput {
    fn write_fmt(
        &mut self, args: fmt::Arguments<'_>
    ) -> Result<(), io::Error>;

    async fn flush(&mut self) -> Result<(), io::Error>;
}

impl<W: io::Write> WriteOutput for W {
    fn write_fmt(
        &mut self, args: fmt::Arguments<'_>
    ) -> Result<(), io::Error> {
        io::Write::write_fmt(self, args)
    }

    async fn flush(&mut self) -> Result<(), io::Error> {
        Ok(())
    }
}


//------------ FrameWriter ---------------------------------------------------

pub struct FrameWriter {
    /// The frame we are currently writing to.
    frame: Vec<u8>,

    /// The maximum size of each frame.
    ///
    /// Whenever the frame reaches this size, it is being send off.
    frame_size: usize,

    /// The destination of a completed frame.
    tx: mpsc::Sender<Vec<u8>>
}

impl FrameWriter {
    pub fn new() -> (Self, mpsc::Receiver<Vec<u8>>) {
        let (tx, rx) = mpsc::channel(1);
        (
            Self {
                frame: Vec::new(),
                frame_size: 0xFFFF,
                tx
            },
            rx
        )
    }
}

impl WriteOutput for FrameWriter {
    fn write_fmt(
        &mut self, args: fmt::Arguments<'_>
    ) -> Result<(), io::Error> {
        io::Write::write_fmt(&mut self.frame, args)
    }

    async fn flush(&mut self) -> Result<(), io::Error> {
        if self.frame.len() > self.frame_size {
            let frame = mem::take(&mut self.frame);
            self.tx.send(frame).await.map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "broken pipe")
            })?;
        }
        Ok(())
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

                let mut metrics = Metrics::new();
                metrics.time = datetime;
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

