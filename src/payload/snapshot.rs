//! The collection of all payload data resulting from a validation run.
//!
//! This is a private module. Its public types are re-exported by the parent.

#![allow(dead_code)]

use std::sync::Arc;
use chrono::{DateTime, Utc};
use rpki::repository::x509::Time;
use rpki::rtr::payload::{
    Aspa, PayloadRef, PayloadType, RouteOrigin, RouterKey
};
use rpki::rtr::server::PayloadSet;
use super::info::PayloadInfo;


//------------ PayloadSnapshot -----------------------------------------------

/// The complete set of validated payload data.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct PayloadSnapshot {
    /// The route origins.
    origins: PayloadCollection<RouteOrigin>,

    /// The router keys,
    router_keys: PayloadCollection<RouterKey>,

    /// The AS providers,
    aspas: PayloadCollection<Aspa>,

    /// The time when this snapshot was created.
    created: DateTime<Utc>,

    /// The time when this snapshot needs to be refreshed at the latest.
    refresh: Option<Time>,
}


//--- Default

impl Default for PayloadSnapshot {
    fn default() -> Self {
        PayloadSnapshot {
            origins: Default::default(),
            router_keys: Default::default(),
            aspas: Default::default(),
            created: Utc::now(),
            refresh: None
        }
    }
}

impl PayloadSnapshot {
    /// Creates a new snapshot from its parts.
    pub(super) fn new(
        origins: impl Iterator<Item = (RouteOrigin, PayloadInfo)>,
        router_keys: impl Iterator<Item = (RouterKey, PayloadInfo)>,
        aspas: impl Iterator<Item = (Aspa, PayloadInfo)>,
        refresh: Option<Time>
    ) -> Self {
        Self {
            origins: PayloadCollection::from_iter(origins),
            router_keys: PayloadCollection::from_iter(router_keys),
            aspas: PayloadCollection::from_iter(aspas),
            created: Utc::now(),
            refresh,
        }
    }

    /// Returns when this snapshot was created.
    pub fn created(&self) -> DateTime<Utc> {
        self.created
    }

    /// Returns when this snapshot should be refreshed at the latest.
    ///
    /// Returns `None` if there is no known refresh time.
    pub fn refresh(&self) -> Option<Time> {
        self.refresh
    }

    /// Returns an iteratore over all payload.
    pub fn payload(
        &self
    ) -> impl Iterator<Item = PayloadRef> {
        self.origins.iter_payload().chain(
            self.router_keys.iter_payload()
        ).chain(
            self.aspas.iter_payload()
        )
    }

    /// Returns an iterator over references to route origins.
    pub fn origin_refs(
        &self
    ) -> impl Iterator<Item = (&RouteOrigin, &PayloadInfo)> + '_ {
        self.origins.iter()
    }

    /// Returns an iterator over the route origins.
    pub fn origins(
        &self
    ) -> impl Iterator<Item = (RouteOrigin, &PayloadInfo)> + '_ {
        self.origins.iter().map(|(origin, info)| (*origin, info))
    }

    /// Returns an iterator over route origins as payload.
    pub fn origin_payload(
        &self
    ) -> impl Iterator<Item = PayloadRef> {
        self.origins.iter_payload()
    }

    /// Returns an interator over the router keys.
    pub fn router_keys(
        &self
    ) -> impl Iterator<Item = (&RouterKey, &PayloadInfo)> + '_ {
        self.router_keys.iter()
    }

    /// Returns an iterator over router keys as payload.
    pub fn router_key_payload(
        &self
    ) -> impl Iterator<Item = PayloadRef> {
        self.router_keys.iter_payload()
    }

    /// Returns an interator over the AS providers.
    pub fn aspas(
        &self
    ) -> impl Iterator<Item = (&Aspa, &PayloadInfo)> + '_ {
        self.aspas.iter()
    }

    /// Returns an iterator over ASPAs as payload.
    pub fn aspa_payload(
        &self
    ) -> impl Iterator<Item = PayloadRef> {
        self.aspas.iter_payload()
    }

    /// Returns an iterator over the payload of a shared snapshot.
    pub fn arc_iter(self: Arc<Self>) -> SnapshotArcIter {
        SnapshotArcIter::new(self)
    }

    /// Returns an iterator over the origins of a shared snapshot.
    pub fn arc_origins_iter(self: Arc<Self>) -> SnapshotArcOriginsIter {
        SnapshotArcOriginsIter::new(self)
    }

    /// Returns an iterator over the router keys of a shared snapshot.
    pub fn arc_router_keys_iter(self: Arc<Self>) -> SnapshotArcRouterKeysIter {
        SnapshotArcRouterKeysIter::new(self)
    }

    /// Returns an iterator over the ASPAs of a shared snapshot.
    pub fn arc_aspas_iter(self: Arc<Self>) -> SnapshotArcAspasIter {
        SnapshotArcAspasIter::new(self)
    }
}


//--- AsRef

impl AsRef<PayloadSnapshot> for PayloadSnapshot {
    fn as_ref(&self) -> &Self {
        self
    }
}


//------------ PayloadCollection ---------------------------------------------

/// An ordered collection of payload.
#[derive(Clone, Debug)]
struct PayloadCollection<P> {
    vec: Vec<(P, PayloadInfo)>,
}

impl<P> Default for PayloadCollection<P> {
    fn default() -> Self {
        Self { vec: Default::default() }
    }
}

impl<P> PayloadCollection<P> {
    /// Creates a collection from a possibly unsorted vec.
    pub fn from_vec(mut vec: Vec<(P, PayloadInfo)>) -> Self
    where P: Ord {
        vec.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        Self { vec}
    }

    /// Returns the length of the collection.
    pub fn len(&self) -> usize {
        self.vec.len()
    }

    /// Returns the item with the given index.
    ///
    /// Returns `None` if `idx` is out of bounds.
    pub fn get(&self, idx: usize) -> Option<(&P, &PayloadInfo)> {
        self.vec.get(idx).map(|item| (&item.0, &item.1))
    }

    /// Returns an iterator over the payload.
    pub fn iter(&self) -> impl Iterator<Item = (&P, &PayloadInfo)> {
        self.vec.iter().map(|item| (&item.0, &item.1))
    }

    /// Returns an iterator over the payload.
    pub fn iter_ref(&self) -> impl Iterator<Item = (PayloadRef, &PayloadInfo)>
    where for<'a> &'a P: Into<PayloadRef<'a>> {
        self.vec.iter().map(|item| ((&item.0).into(), &item.1))
    }

    /// Returns an iterator over just the payload.
    pub fn iter_payload(&self) -> impl Iterator<Item = PayloadRef>
    where for<'a> &'a P: Into<PayloadRef<'a>> {
        self.vec.iter().map(|item| (&item.0).into())
    }
}

impl<P: Ord> FromIterator<(P, PayloadInfo)> for PayloadCollection<P> {
    fn from_iter<I: IntoIterator<Item = (P, PayloadInfo)>>(iter: I) -> Self {
        Self::from_vec(
            iter.into_iter().collect()
        )
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for PayloadCollection<RouteOrigin> {
    fn arbitrary(
        u: &mut arbitrary::Unstructured<'a>
    ) -> arbitrary::Result<Self> {
        let mut vec = Vec::<(RouteOrigin, PayloadInfo)>::arbitrary(u)?;
        vec.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        vec.dedup_by(|left, right| left.0 == right.0);
        Ok(Self { vec })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for PayloadCollection<RouterKey> {
    fn arbitrary(
        u: &mut arbitrary::Unstructured<'a>
    ) -> arbitrary::Result<Self> {
        let mut vec = Vec::<(RouterKey, PayloadInfo)>::arbitrary(u)?;
        vec.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        vec.dedup_by(|left, right| left.0 == right.0);
        Ok(Self { vec })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for PayloadCollection<Aspa> {
    fn arbitrary(
        u: &mut arbitrary::Unstructured<'a>
    ) -> arbitrary::Result<Self> {
        let mut vec = Vec::<(Aspa, PayloadInfo)>::arbitrary(u)?;
        vec.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        vec.dedup_by(|left, right| left.0.key() == right.0.key());
        Ok(Self { vec })
    }
}


//----------- SnapshotArcIter ------------------------------------------------

/// An iterator over the VRPs of a shared snapshot.
#[derive(Clone, Debug)]
pub struct SnapshotArcIter {
    /// The shared snapshot.
    snapshot: Arc<PayloadSnapshot>,

    /// The payload type we currently are processing.
    current_type: PayloadType,

    /// The index into the list of that payload type that is next to return.
    next: usize,
}

impl SnapshotArcIter {
    /// Creates a new iterator from a shared snapshot.
    fn new(snapshot: Arc<PayloadSnapshot>) -> Self {
        Self {
            snapshot,
            current_type: PayloadType::Origin,
            next: 0,
        }
    }

    /// Returns the next item and its information.
    pub fn next_with_info(&mut self) -> Option<(PayloadRef, &PayloadInfo)> {
        if matches!(self.current_type, PayloadType::Origin) {
            if let Some(res) = self.snapshot.origins.get(self.next) {
                self.next += 1;
                return Some((res.0.into(), res.1));
            }
            self.current_type = PayloadType::RouterKey;
            self.next = 0;
        }
        if matches!(self.current_type, PayloadType::RouterKey) {
            if let Some(res) = self.snapshot.router_keys.get(self.next) {
                self.next += 1;
                return Some((res.0.into(), res.1))
            }
            self.current_type = PayloadType::Aspa;
            self.next = 0;
        }
        assert!(matches!(self.current_type, PayloadType::Aspa));
        let res = self.snapshot.aspas.get(self.next)?;
        self.next += 1;
        Some((res.0.into(), res.1))
    }
}

impl PayloadSet for SnapshotArcIter {
    fn next(&mut self) -> Option<PayloadRef> {
        self.next_with_info().map(|(res, _)| res)
    }
}


//------------ SnapshotArcOriginsIter ----------------------------------------

/// An iterator over the route origins in a shared snapshot.
#[derive(Clone, Debug)]
pub struct SnapshotArcOriginsIter {
    /// The snapshot we iterate over.
    snapshot: Arc<PayloadSnapshot>,

    /// The index of the next item in the current origin list.
    next: usize
}

impl SnapshotArcOriginsIter {
    /// Creates a new iterator from a shared snapshot.
    fn new(snapshot: Arc<PayloadSnapshot>) -> Self {
        Self {
            snapshot,
            next: 0,
        }
    }

    /// Returns the next item and its information.
    pub fn next_with_info(&mut self) -> Option<(RouteOrigin, &PayloadInfo)> {
        let (origin, info) = self.snapshot.origins.get(self.next)?;
        self.next += 1;
        Some((*origin, info))
    }
}

impl Iterator for SnapshotArcOriginsIter {
    type Item = RouteOrigin;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_with_info().map(|item| item.0)
    }
}


//------------ SnapshotArcRouterKeysIter -------------------------------------

/// An iterator over the router keys in a shared snapshot.
#[derive(Clone, Debug)]
pub struct SnapshotArcRouterKeysIter {
    /// The snapshot we iterate over.
    snapshot: Arc<PayloadSnapshot>,

    /// The index of the next item in ther outer key list.
    next: usize
}

impl SnapshotArcRouterKeysIter {
    /// Creates a new iterator from a shared snapshot.
    fn new(snapshot: Arc<PayloadSnapshot>) -> Self {
        Self {
            snapshot,
            next: 0,
        }
    }

    /// Returns the next item and its information.
    pub fn next_with_info(&mut self) -> Option<(&RouterKey, &PayloadInfo)> {
        let res = self.snapshot.router_keys.get(self.next)?;
        self.next += 1;
        Some(res)
    }
}


//------------ SnapshotArcAspasIter ------------------------------------------

/// An iterator over the ASPA elements in a shared snapshot.
#[derive(Clone, Debug)]
pub struct SnapshotArcAspasIter {
    /// The snapshot we iterate over.
    snapshot: Arc<PayloadSnapshot>,

    /// The index of the next item in ther outer key list.
    next: usize
}

impl SnapshotArcAspasIter {
    /// Creates a new iterator from a shared snapshot.
    fn new(snapshot: Arc<PayloadSnapshot>) -> Self {
        Self {
            snapshot,
            next: 0,
        }
    }

    /// Returns the next item and its information.
    pub fn next_with_info(&mut self) -> Option<(&Aspa, &PayloadInfo)> {
        self.snapshot.aspas.get(self.next).map(|res| { self.next +=1; res })
        /*
        let (payload, info) = self.snapshot.aspas.get(self.next)?;
        self.next += 1;
        match payload {
            Payload::Aspa(aspa) => Some((aspa, info)),
            _ => panic!("non-router key in router key set")
        }
        */
    }
}
 
