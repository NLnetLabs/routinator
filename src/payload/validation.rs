//! Collecting payload during validation.
//!
//! This module contains the types necessary to collect payload during a
//! validation run. It is a private module. The public types of this module
//! are re-exported by the parent.
//!
//! [`ValidationReport`] collects the data derived from validating each
//! publication point. This data is derived by [`PubPointProcessor`] which
//! is used by the [`Engine`][crate::engine::Engine] during a validation run.
//! The resources of each publication point are stored in [`PubPoint`].
//! 
//! [`RejectedResources`] and its [`RejectedResourcesBuilder`] collect
//! prefixes and AS numbers from certificates for which publication points
//! had to be rejected so we can avoid partial VRP coverage.

use std::cmp;
use std::collections::hash_map;
use std::collections::HashMap;
use std::sync::Arc;
use crossbeam_queue::SegQueue;
use log::{info, warn};
use routecore::addr;
use routecore::asn::{Asn, SmallAsnSet};
use routecore::bgpsec::KeyIdentifier;
use rpki::uri;
use rpki::repository::aspa::AsProviderAttestation;
use rpki::repository::cert::{Cert, ResourceCert};
use rpki::repository::resources::{
    AsBlock, AsBlocks, IpBlock, IpBlocks, IpBlocksBuilder,
};
use rpki::repository::roa::RouteOriginAttestation;
use rpki::repository::tal::{Tal, TalUri};
use rpki::repository::x509::{Time, Validity};
use rpki::rtr::payload::{Afi, Aspa, RouteOrigin, RouterKey};
use rpki::rtr::pdu::{ProviderAsns, RouterKeyInfo};
use crate::config::{Config, FilterPolicy};
use crate::engine::{CaCert, Engine, ProcessPubPoint, ProcessRun};
use crate::error::Failed;
use crate::metrics::{Metrics, PayloadMetrics, VrpMetrics};
use crate::slurm::LocalExceptions;
use super::info::{PayloadInfo, PublishInfo};
use super::snapshot::PayloadSnapshot;


//------------ ValidationReport ----------------------------------------------

/// The payload set resulting from a validation run.
#[derive(Debug)]
pub struct ValidationReport {
    /// The data from all the valid publication points.
    ///
    /// When a publication point has been successfully validated, it pushes
    /// its data to this queue.
    pub_points: SegQueue<PubPoint>,

    /// Filter for invalid resources.
    ///
    /// If a publication point is rejected, the resources from its CA
    /// certificate are added to this.
    rejected: RejectedResourcesBuilder,

    /// Should we log rejected resources?
    log_rejected: bool,

    /// Should we include BGPsec router keys?
    enable_bgpsec: bool,

    /// Should we include ASPA objects?
    enable_aspa: bool,

    /// Should we filter IPv4 prefixes longer than a certain length?
    limit_v4_len: Option<u8>,

    /// Should we filter IPv6 prefixes longer than a certain length?
    limit_v6_len: Option<u8>,

    /// How are we dealing with unsafe VRPs?
    unsafe_vrps: FilterPolicy,
}

impl ValidationReport {
    /// Creates a new, empty validation report.
    pub fn new(config: &Config) -> Self {
        ValidationReport {
            pub_points: Default::default(),
            rejected: Default::default(),
            log_rejected: config.unsafe_vrps.log(),
            enable_bgpsec: config.enable_bgpsec,
            enable_aspa: config.enable_aspa,
            limit_v4_len: config.limit_v4_len,
            limit_v6_len: config.limit_v6_len,
            unsafe_vrps: config.unsafe_vrps,
        }
    }

    /// Creates a new validation report by running the engine.
    pub fn process(
        engine: &Engine, config: &Config,
    ) -> Result<(Self, Metrics), Failed> {
        let report = Self::new(config);
        let mut run = engine.start(&report)?;
        run.process()?;
        run.cleanup()?;
        let metrics = run.done();
        Ok((report, metrics))
    }

    /// Converts the report into a payload snapshot.
    pub fn into_snapshot(
        self,
        exceptions: &LocalExceptions,
        metrics: &mut Metrics,
    ) -> PayloadSnapshot {
        let mut builder = SnapshotBuilder::new(
            self.rejected.finalize(), self.unsafe_vrps,
            exceptions,
        );
        while let Some(point) = self.pub_points.pop() {
            builder.process_pub_point(point, metrics)
        }
        builder.finalize(metrics)
    }
}

impl<'a> ProcessRun for &'a ValidationReport {
    type PubPoint = PubPointProcessor<'a>;

    fn process_ta(
        &self,
        _tal: &Tal, _uri: &TalUri, cert: &CaCert,
        tal_index: usize,
    ) -> Result<Option<Self::PubPoint>, Failed> {
        Ok(Some(
            PubPointProcessor {
                report: self,
                pub_point: PubPoint::new_ta(cert, tal_index),
                validity: cert.combined_validity(),
            }
        ))
    }
}


//------------ PubPointProcessor ---------------------------------------------

/// Collects all the data for a publication point.
///
/// This type is used during validation of a publication point. It collects
/// all the published data and eventually contributes it to a validation
/// report.
#[derive(Clone, Debug)]
pub struct PubPointProcessor<'a> {
    /// The validation report payload is contributed to.
    report: &'a ValidationReport,

    /// The data being collected.
    pub_point: PubPoint,

    /// The (combined) validity of the CA certificate.
    validity: Validity,
}

impl<'a> ProcessPubPoint for PubPointProcessor<'a> {
    fn repository_index(&mut self, repository_index: usize) {
        self.pub_point.repository_index = Some(repository_index)
    }

    fn update_refresh(&mut self, not_after: Time) {
        self.pub_point.refresh = cmp::min(
            self.pub_point.refresh, not_after
        );
    }

    fn want(&self, _uri: &uri::Rsync) -> Result<bool, Failed> {
        // While we actually only care for some types, we want everything
        // processed for statistics.
        Ok(true)
    }

    fn process_ca(
        &mut self, _uri: &uri::Rsync, cert: &CaCert,
    ) -> Result<Option<Self>, Failed> {
        Ok(Some(
            PubPointProcessor {
                report: self.report,
                pub_point: PubPoint::new_ca(&self.pub_point, cert),
                validity: cert.combined_validity(),
            }
        ))
    }

    fn process_ee_cert(
        &mut self, uri: &uri::Rsync, cert: Cert, ca_cert: &CaCert,
    ) -> Result<(), Failed> {
        if !self.report.enable_bgpsec {
            return Ok(())
        }
        if
            cert.as_resources().is_inherited()
            || !cert.as_resources().is_present()
        {
            warn!(
                "{}: router certificate does not contain AS resources.", uri
            );
            return Ok(())
        }
        let asns = match cert.as_resources().to_blocks() {
            Ok(blocks) => blocks,
            Err(_) => {
                warn!(
                    "{}: router certificate contains invalid AS resources.",
                    uri
                );
                return Ok(())
            }
        };
        let id = cert.subject_key_identifier();
        let key = cert.subject_public_key_info();
        if !key.allow_router_cert() {
            warn!(
                "{}: router certificate has invalid key algorithm.", uri
            );
            return Ok(())
        }
        let key = match RouterKeyInfo::new(key.to_info_bytes()) {
            Ok(key) => key,
            Err(_) => {
                warn!(
                    "{}: excessively large key in router certificate.", uri
                );
                return Ok(())
            }
        };
        self.pub_point.update_refresh(cert.validity().not_after());
        self.pub_point.add_router_key(
            asns, id, key, Arc::new(PublishInfo::ee_cert(&cert, uri, ca_cert))
        );
        Ok(())
    }

    fn process_roa(
        &mut self,
        _uri: &uri::Rsync,
        cert: ResourceCert,
        route: RouteOriginAttestation
    ) -> Result<(), Failed> {
        if self.pub_point.add_roa(
            route, Arc::new(PublishInfo::signed_object(&cert, self.validity)),
            self.report.limit_v4_len, self.report.limit_v6_len,
        ) {
            self.pub_point.update_refresh(cert.validity().not_after());
        }
        Ok(())
    }

    fn process_aspa(
        &mut self,
        _uri: &uri::Rsync,
        cert: ResourceCert,
        aspa: AsProviderAttestation
    ) -> Result<(), Failed> {
        if !self.report.enable_aspa {
            return Ok(())
        }
        self.pub_point.update_refresh(cert.validity().not_after());
        self.pub_point.add_aspa(
            aspa, Arc::new(PublishInfo::signed_object(&cert, self.validity))
        );
        Ok(())
    }

    fn restart(&mut self) -> Result<(), Failed> {
        self.pub_point.restart();
        Ok(())
    }

    fn commit(self) {
        if !self.pub_point.is_empty() {
            self.report.pub_points.push(self.pub_point);
        }
    }

    fn cancel(self, cert: &CaCert) {
        if self.report.log_rejected {
            warn!(
                "CA for {} rejected, resources marked as unsafe:",
                cert.ca_repository()
            );
            for block in cert.cert().v4_resources().iter() {
                warn!("   {}", block.display_v4());
            }
            for block in cert.cert().v6_resources().iter() {
                warn!("   {}", block.display_v6());
            }
            for block in cert.cert().as_resources().iter() {
                warn!("   {}", block);
            }
        }
        self.report.rejected.extend_from_cert(cert);
    }
}


//------------ PubPoint ------------------------------------------------------

/// The raw data published by a publication point.
///
/// This type collects all the data published so it is available for later
/// processing.
#[derive(Clone, Debug)]
pub struct PubPoint {
    /// The list of valid route origins.
    origins: Vec<PubRouteOrigin>,

    /// The list of valid router keys.
    router_keys: Vec<PubRouterKey>,

    /// The list of valid ASPA payload.
    aspas: Vec<PubAspa>,

    /// The time when the publication point needs to be refreshed.
    refresh: Time,

    /// The initial value of `refresh`.
    ///
    /// We need this for restarting processing.
    orig_refresh: Time,

    /// The index of the TALs for the payload in the metrics.
    tal_index: usize,

    /// The index of the repository containing the payload in the metrics.
    repository_index: Option<usize>,
}

impl PubPoint {
    /// Creates a new publication point.
    fn new(refresh: Time, tal_index: usize) -> Self {
        PubPoint {
            origins: Vec::new(),
            router_keys: Vec::new(),
            aspas: Vec::new(),
            refresh,
            orig_refresh: refresh,
            tal_index,
            repository_index: None,
        }
    }

    /// Creates a new publication point for a trust anchor CA.
    fn new_ta(cert: &CaCert, tal_index: usize) -> Self {
        Self::new(cert.cert().validity().not_after(), tal_index)
    }

    /// Creates a new publication for a regular CA.
    fn new_ca(parent: &PubPoint, cert: &CaCert) -> Self {
        Self::new(
            cmp::min(
                parent.refresh, cert.cert().validity().not_after()
            ),
            parent.tal_index,
        )
    }

    /// Returns whether there is nothing published via this point.
    pub fn is_empty(&self) -> bool {
        self.origins.is_empty()
        && self.router_keys.is_empty()
        && self.aspas.is_empty()
    }

    /// Updates the refresh time to be no later than the given time.
    fn update_refresh(&mut self, refresh: Time) {
        self.refresh = cmp::min(self.refresh, refresh)
    }

    /// Restarts processing for the publication point.
    fn restart(&mut self) {
        self.origins.clear();
        self.router_keys.clear();
        self.aspas.clear();
        self.refresh = self.orig_refresh;
    }

    /// Adds the content of a ROA to the payload.
    fn add_roa(
        &mut self,
        roa: RouteOriginAttestation,
        info: Arc<PublishInfo>,
        limit_v4_len: Option<u8>,
        limit_v6_len: Option<u8>,
    ) -> bool {
        let mut any = false;
        for origin in roa.iter_origins() {
            let limit = if origin.prefix.prefix().is_v4() {
                limit_v4_len
            }
            else {
                limit_v6_len
            };
            if let Some(limit) = limit {
                if origin.prefix.prefix().len() > limit {
                    continue;
                }
            }
            self.origins.push(PubRouteOrigin { origin, info: info.clone() });
            any = true;
        }
        any
    }

    /// Adds the content of a router key to the payload.
    fn add_router_key(
        &mut self,
        asns: AsBlocks,
        key_id: KeyIdentifier,
        key_info: RouterKeyInfo,
        info: Arc<PublishInfo>,
    ) {
        self.router_keys.push(
            PubRouterKey { asns, key_id, key_info, info }
        );
    }

    /// Adds the content of an ASPA object to the payload.
    fn add_aspa(
        &mut self,
        aspa: AsProviderAttestation,
        info: Arc<PublishInfo>,
    ) {
        let v4_providers = SmallAsnSet::from_iter(
            aspa.provider_as_set().iter().filter_map(|item| {
                item.includes_v4().then(|| item.provider())
            })
        );
        let v6_providers = SmallAsnSet::from_iter(
            aspa.provider_as_set().iter().filter_map(|item| {
                item.includes_v4().then(|| item.provider())
            })
        );

        self.aspas.push(
            PubAspa {
                customer: aspa.customer_as(),
                v4_providers: if v4_providers.is_empty() {
                    SmallAsnSet::from_iter([Asn::from(0)])
                }
                else {
                    v4_providers
                },
                v6_providers: if v6_providers.is_empty() {
                    SmallAsnSet::from_iter([Asn::from(0)])
                }
                else {
                    v6_providers
                },
                info
            }
        )
    }
}


//------------ PubRouteOrigin ------------------------------------------------

#[derive(Clone, Debug)]
pub struct PubRouteOrigin {
    pub origin: RouteOrigin,
    pub info: Arc<PublishInfo>,
}


//------------ PubRouterKey --------------------------------------------------

/// The raw information from a router key certificate.
#[derive(Clone, Debug)]
pub struct PubRouterKey {
    pub asns: AsBlocks,
    pub key_id: KeyIdentifier,
    pub key_info: RouterKeyInfo,
    pub info: Arc<PublishInfo>,
}


//------------ PubAspa -------------------------------------------------------

/// The raw information from a published ASPA object.
#[derive(Clone, Debug)]
pub struct PubAspa {
    pub customer: Asn,
    pub v4_providers: SmallAsnSet,
    pub v6_providers: SmallAsnSet,
    pub info: Arc<PublishInfo>,
}


//------------ RejectedResources ---------------------------------------------

/// The resources from publication points that had to be rejected.
#[derive(Clone, Debug)]
pub struct RejectedResources {
    v4: IpBlocks,
    v6: IpBlocks,
}

impl RejectedResources {
    /// Checks whether a prefix should be kept.
    pub fn keep_prefix(&self, prefix: addr::Prefix) -> bool {
        let raw = rpki::repository::resources::Prefix::new(
            prefix.addr(), prefix.len()
        );
        if prefix.is_v4() {
            !self.v4.intersects_block(raw)
        }
        else {
            !self.v6.intersects_block(raw)
        }
    }
}


//------------ RejectedResourcesBuilder --------------------------------------

/// A builder for invalid resources encountered during validation.
#[derive(Debug, Default)]
struct RejectedResourcesBuilder {
    /// The queue of rejected IP blocks.
    ///
    /// The first element is whether the block is for IPv4.
    addrs: SegQueue<(bool, IpBlock)>,

    /// The queue of rejected AS blocks.
    asns: SegQueue<AsBlock>,
}

impl RejectedResourcesBuilder {
    fn extend_from_cert(&self, cert: &CaCert) {
        for block in cert.cert().v4_resources().iter().filter(|block|
            !block.is_slash_zero()
        ) {
            self.addrs.push((true, block));
        }
        for block in cert.cert().v6_resources().iter().filter(|block|
            !block.is_slash_zero()
        ) {
            self.addrs.push((false, block));
        }
        for block in cert.cert().as_resources().iter().filter(|block|
            !block.is_whole_range()
        ) {
            self.asns.push(block)
        }
    }

    fn finalize(self) -> RejectedResources {
        let mut v4 = IpBlocksBuilder::new();
        let mut v6 = IpBlocksBuilder::new();
        while let Some((is_v4, block)) = self.addrs.pop() {
            if is_v4 {
                v4.push(block);
            }
            else {
                v6.push(block);
            }
        }
        RejectedResources {
            v4: v4.finalize(),
            v6: v6.finalize(),
        }
    }
}


//------------ SnapshotBuilder -----------------------------------------------

/// Helps turning the report into a payload snapshot.
struct SnapshotBuilder<'a> {
    /// The collected route origins.
    origins: HashMap<RouteOrigin, PayloadInfo>,

    /// The collected router keys.
    router_keys: HashMap<RouterKey, PayloadInfo>,

    /// The collected ASPA payload.
    ///
    /// The key is the customer ASN.
    aspas: HashMap<(Asn, Afi), (SmallAsnSet, PayloadInfo)>,

    /// The list of rejected resources.
    rejected: RejectedResources,

    /// How are we dealing with unsafe VRPs?
    unsafe_vrps: FilterPolicy,

    /// Are unsafe VRPs present?
    unsafe_vrps_present: bool,

    /// The time when this snapshot needs to be refreshed at the latest.
    refresh: Option<Time>,

    exceptions: &'a LocalExceptions,
}

impl<'a> SnapshotBuilder<'a> {
    fn new(
        rejected: RejectedResources,
        unsafe_vrps: FilterPolicy,
        exceptions: &'a LocalExceptions,
        
    ) -> Self {
        Self {
            origins: Default::default(),
            router_keys: Default::default(),
            aspas: Default::default(),
            rejected,
            unsafe_vrps,
            unsafe_vrps_present: false,
            refresh: None,
            exceptions,
        }
    }


    fn process_pub_point(
        &mut self, point: PubPoint, metrics: &mut Metrics
    ) {
        let mut metrics = AllVrpMetrics::new(
            metrics, point.tal_index, point.repository_index,
        );
        self.update_refresh(point.refresh);
        point.origins.into_iter().for_each(|item| {
            self.process_origin(item, &mut metrics)
        });
        point.router_keys.into_iter().for_each(|item| {
            self.process_key(item, &mut metrics)
        });
        point.aspas.into_iter().for_each(|item| {
            self.process_aspa(item, &mut metrics)
        });
    }

    /// Updates the refresh time.
    fn update_refresh(&mut self, refresh: Time) {
        self.refresh = match self.refresh {
            Some(old) => Some(cmp::min(old, refresh)),
            None => Some(refresh)
        }
    }

    fn process_origin(
        &mut self, origin: PubRouteOrigin, metrics: &mut AllVrpMetrics,
    ) {
        let v4 = origin.origin.is_v4();
        metrics.update_origin(v4, |m| m.valid += 1);

        // Is the prefix in the rejected resources?
        if !self.rejected.keep_prefix(origin.origin.prefix.prefix()) {
            self.unsafe_vrps_present = true;
            match self.unsafe_vrps {
                FilterPolicy::Accept => {
                    // Don’t count, don’t warn ...
                }
                FilterPolicy::Warn => {
                    metrics.update_origin(v4, |m| m.marked_unsafe += 1);
                    info!(
                        "Encountered potentially unsafe VRP \
                         ({}/{}-{}, {})",
                        origin.origin.prefix.addr(),
                        origin.origin.prefix.prefix_len(),
                        origin.origin.prefix.resolved_max_len(),
                        origin.origin.asn
                    );
                }
                FilterPolicy::Reject => {
                    metrics.update_origin(v4, |m| m.marked_unsafe += 1);
                    warn!(
                        "Filtering potentially unsafe VRP \
                         ({}/{}-{}, {})",
                        origin.origin.prefix.addr(),
                        origin.origin.prefix.prefix_len(),
                        origin.origin.prefix.resolved_max_len(),
                        origin.origin.asn
                    );
                    return
                }
            }
        }

        // Is the origin to be filtered locally?
        if self.exceptions.drop_origin(origin.origin) {
            metrics.update_origin(v4, |m| m.locally_filtered += 1);
            return
        }

        // Insert the origin. If we have it already, we need to
        // update its info instead.
        match self.origins.entry(origin.origin) {
            hash_map::Entry::Vacant(entry) => {
                entry.insert(origin.info.into());
                metrics.update_origin(v4, |m| m.contributed += 1);
            }
            hash_map::Entry::Occupied(mut entry) => {
                entry.get_mut().add_published(origin.info);
                metrics.update_origin(v4, |m| m.duplicate += 1);
            }
        }
    }

    fn process_key(
        &mut self, key: PubRouterKey, metrics: &mut AllVrpMetrics,
    ) {
        metrics.update(|m| m.router_keys.valid += key.asns.asn_count());

        // Now for each ASN.
        for asn in key.asns.iter_asns() {
            // Insert the key. If we have it already, we need to
            // update its info instead.
            match self.router_keys.entry(
                RouterKey::new(key.key_id, asn, key.key_info.clone())
            ) {
                hash_map::Entry::Vacant(entry) => {
                    entry.insert(key.info.clone().into());
                    metrics.update( |m| m.router_keys.contributed += 1);
                }
                hash_map::Entry::Occupied(mut entry) => {
                    entry.get_mut().add_published(key.info.clone());
                    metrics.update( |m| m.router_keys.duplicate += 1);
                }
            }
        }
    }

    fn process_aspa(&mut self, aspa: PubAspa, metrics: &mut AllVrpMetrics) {
        metrics.update(|m| m.aspas.valid += 1);

        let (mut contributed, mut duplicate) = (false, false);

        if !aspa.v4_providers.is_empty() {
            if self.process_aspa_family(
                aspa.customer, Afi::ipv4(), aspa.v4_providers,
                aspa.info.clone(), metrics,
            ) {
                contributed = true;
            }
            else {
                duplicate = true;
            }
        }
        if !aspa.v6_providers.is_empty() {
            if self.process_aspa_family(
                aspa.customer, Afi::ipv6(), aspa.v6_providers,
                aspa.info, metrics,
            ) {
                contributed = true;
            }
            else {
                duplicate = true;
            }
        }

        if contributed {
            metrics.update(|m| m.aspas.contributed += 1);
        }
        if duplicate {
            metrics.update(|m| m.aspas.duplicate += 1);
        }
    }

    fn process_aspa_family(
        &mut self,
        customer: Asn,
        afi: Afi,
        providers: SmallAsnSet,
        info: Arc<PublishInfo>,
        _metrics: &mut AllVrpMetrics,
    ) -> bool {
        // SLURM filtering goes here ...

        match self.aspas.entry((customer, afi)) {
            hash_map::Entry::Vacant(entry) => {
                entry.insert((providers, info.into()));
                true
            }
            hash_map::Entry::Occupied(mut entry) => {
                let entry = entry.get_mut();
                entry.0 = entry.0.union(&providers).collect();
                entry.1.add_published(info);
                false
            }
        }
    }

    fn finalize(mut self, metrics: &mut Metrics) -> PayloadSnapshot {
        if self.unsafe_vrps_present && self.unsafe_vrps.log()  {
            warn!(
                "For more information on unsafe VRPs, see \
                 https://routinator.docs.nlnetlabs.nl\
                 /en/stable/unsafe-vrps.html"
            );
        }

        self.insert_assertions(metrics);
        metrics.finalize();
        self.into_snapshot()
    }

    fn insert_assertions(&mut self, metrics: &mut Metrics) {
        for (origin, info) in self.exceptions.origin_assertions() {
            match self.origins.entry(origin) {
                hash_map::Entry::Vacant(entry) => {
                    entry.insert(info.into());
                    if origin.is_v4() {
                        metrics.local.v4_origins.contributed += 1;
                        metrics.payload.v4_origins.contributed += 1;
                    }
                    else {
                        metrics.local.v6_origins.contributed += 1;
                        metrics.payload.v6_origins.contributed += 1;
                    }
                }
                hash_map::Entry::Occupied(mut entry) => {
                    entry.get_mut().add_local(info);
                    if origin.is_v4() {
                        metrics.local.v4_origins.duplicate += 1;
                        metrics.payload.v4_origins.duplicate += 1;
                    }
                    else {
                        metrics.local.v6_origins.duplicate += 1;
                        metrics.payload.v6_origins.duplicate += 1;
                    }
                }
            }
        }

        for (key, info) in self.exceptions.router_key_assertions() {
            match self.router_keys.entry(key) {
                hash_map::Entry::Vacant(entry) => {
                    entry.insert(info.into());
                    metrics.local.router_keys.contributed += 1;
                    metrics.payload.router_keys.contributed += 1;
                }
                hash_map::Entry::Occupied(mut entry) => {
                    entry.get_mut().add_local(info);
                    metrics.local.router_keys.duplicate += 1;
                    metrics.payload.router_keys.duplicate += 1;
                }
            }
        }

        // XXX ASPA assertions.
    }

    fn into_snapshot(self) -> PayloadSnapshot {
        PayloadSnapshot::new(
            self.origins.into_iter(),
            self.router_keys.into_iter(),
            self.aspas.into_iter().filter_map(
                |((customer, afi), (providers, info))| {
                    match ProviderAsns::try_from_iter(providers.iter()) {
                        Ok(providers) => {
                            Some((Aspa::new(customer, afi, providers), info))
                        }
                        Err(_) => {
                            warn!(
                                "Ignoring excessively large ASPA for {}/{} \
                                 with {} provider ASNs.",
                                customer, afi, providers.len()
                            );
                            None
                        }
                    }
                }
            ),
            self.refresh,
        )
    }
}


//------------ AllVrpMetrics -------------------------------------------------

/// A helper struct to simplify changing all VRP metrics for a repository.
pub struct AllVrpMetrics<'a> {
    tal: &'a mut PayloadMetrics,
    repo: Option<&'a mut PayloadMetrics>,
    all: &'a mut PayloadMetrics,
}

impl<'a> AllVrpMetrics<'a> {
    pub fn new(
        metrics: &'a mut Metrics, tal_index: usize, repo_index: Option<usize>,
    ) -> Self {
        AllVrpMetrics {
            tal: &mut metrics.tals[tal_index].payload,
            repo: match repo_index {
                Some(index) => Some(&mut metrics.repositories[index].payload),
                None => None
            },
            all: &mut metrics.payload,
        }
    }

    pub fn update(&mut self, op: impl Fn(&mut PayloadMetrics)) {
        op(self.tal);
        if let Some(ref mut repo) = self.repo {
            op(repo)
        }
        op(self.all)
    }

    pub fn update_origin(&mut self, v4: bool, op: impl Fn(&mut VrpMetrics)) {
        self.update(|metrics| {
            if v4 {
                op(&mut metrics.v4_origins)
            }
            else {
                op(&mut metrics.v6_origins)
            }
        })
    }
}

