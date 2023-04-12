//! Changes between different version of payload.
//!
//! This is a private module. Its public types are re-exported by the parent.

use std::sync::Arc;
use std::cmp::Ordering;
use rpki::rtr::{Action, PayloadRef, PayloadType, Serial};
use rpki::rtr::payload::{Aspa, RouteOrigin, RouterKey};
use rpki::rtr::server::PayloadDiff;
use super::info::PayloadInfo;
use super::snapshot::PayloadSnapshot;


//------------ PayloadDelta --------------------------------------------------

/// The changes between two payload snapshots.
#[derive(Clone, Debug)]
pub struct PayloadDelta {
    /// The target serial number of this delta.
    ///
    /// This is the serial number of the payload history that this delta will
    /// be resulting in when applied.
    serial: Serial,

    /// The delta for route origins.
    origins: StandardDelta<RouteOrigin>,

    /// The delta for router keys.
    router_keys: StandardDelta<RouterKey>,

    /// The delta for ASPA.
    aspas: AspaDelta,
}

impl PayloadDelta {
    /// Creates an empty delta with the given target serial number.
    pub fn empty(serial: Serial) -> Self {
        PayloadDelta {
            serial,
            origins: Default::default(),
            router_keys: Default::default(),
            aspas: Default::default(),
        }
    }

    /// Construct a new delta between two snapshots.
    ///
    /// Returns `None` if the two snapshots are, in fact, identical.
    pub fn construct(
        old: &PayloadSnapshot, new: &PayloadSnapshot, serial: Serial,
    ) -> Option<Self> {
        let res = Self {
            serial,
            origins: StandardDelta::construct(
                old.origin_refs(), new.origin_refs()
            ),
            router_keys: StandardDelta::construct(
                old.router_keys(), new.router_keys()
            ),
            aspas: AspaDelta::construct(
                old.aspas(), new.aspas()
            )
        };

        if res.is_empty() {
            None
        }
        else {
            Some(res)
        }
    }

    /// Creates a new delta by applying the changes from `new` to `self`.
    ///
    /// The resulting delta will have the serial number from `new`. Its
    /// announced set is everything that is announced by `self` unless it is
    /// withdrawn by `new` plus everything announced by `new` unless it was
    /// withdrawn by `self`. Its withdraw list is everything that is withdrawn
    /// in `self` unless it it was announced again by `new` plus everything
    /// that is withdraw by `new` unless it was announced by `self`.
    pub fn merge(&self, new: &Self) -> Self {
        Self {
            serial: new.serial,
            origins: StandardDelta::merge(&self.origins, &new.origins),
            router_keys: StandardDelta::merge(
                &self.router_keys, &new.router_keys
            ),
            aspas: AspaDelta::merge(&self.aspas, &new.aspas),
        }
    }

    /// Returns whether this is an empty delta.
    ///
    /// A delta is empty if there is nothing announced and nothing withdrawn.
    pub fn is_empty(&self) -> bool {
        self.origins.is_empty()
        && self.router_keys.is_empty()
        && self.aspas.is_empty()
    }

    /// Returns the target serial number of the delta.
    pub fn serial(&self) -> Serial {
        self.serial
    }

    /// Returns the number of announced items.
    pub fn announce_len(&self) -> usize {
        self.origins.announce_len
        + self.router_keys.announce_len
        + self.aspas.announce_len
    }

    /// Returns the number of withdrawn items.
    pub fn withdraw_len(&self) -> usize {
        self.origins.withdraw_len
        + self.router_keys.withdraw_len
        + self.aspas.withdraw_len
    }

    /// Returns an iterator over the changes in a shared delta.
    pub fn arc_iter(self: Arc<Self>) -> DeltaArcIter {
        DeltaArcIter::new(self)
    }
}


//------------ StandardDelta -------------------------------------------------

/// A delta for payload types where the value itself is also the key.
#[derive(Clone, Debug)]
struct StandardDelta<P> {
    /// The changed items.
    ///
    /// This list is ordered by payload.
    items: Vec<(P, Action)>,

    /// The number of annouced items.
    announce_len: usize,

    /// The number of withdrawn items.
    withdraw_len: usize,
}

impl<P> Default for StandardDelta<P> {
    fn default() -> Self {
        Self {
            items: Vec::default(),
            announce_len: 0,
            withdraw_len: 0,
        }
    }
}

impl<P: Clone + Ord> StandardDelta<P> {
    fn construct<'a>(
        mut old_iter: impl Iterator<Item = (&'a P, &'a PayloadInfo)>,
        mut new_iter: impl Iterator<Item = (&'a P, &'a PayloadInfo)>,
    ) -> Self
    where P: 'a {
        let mut items = Self::default();

        let mut opt_old = old_iter.next();
        let mut opt_new = new_iter.next();

        loop {
            let old_item = match opt_old {
                Some((item, _)) => item,
                None => {
                    // Old is finished. The rest of new goes into announced.
                    if let Some((new_item, _)) = opt_new {
                        items.push((new_item.clone(), Action::Announce));
                    }
                    items.extend(
                        new_iter.map(|(x, _)| (x.clone(), Action::Announce))
                    );
                    break;
                }
            };
            let new_item = match opt_new {
                Some((item, _)) => item,
                None => {
                    // New is finished. The rest of old goes into withdraw.
                    items.push((old_item.clone(), Action::Withdraw));
                    items.extend(
                        old_iter.map(|(x, _)| (x.clone(), Action::Withdraw))
                    );
                    break;
                }
            };

            match old_item.cmp(new_item) {
                Ordering::Less => {
                    // Excess old item. Goes into withdraw.
                    items.push((old_item.clone(), Action::Withdraw));
                    opt_old = old_iter.next();
                }
                Ordering::Equal => {
                    // Same. Ignore.
                    opt_old = old_iter.next();
                    opt_new = new_iter.next();
                }
                Ordering::Greater => {
                    // Excess new item. Goes into announce.
                    items.push((new_item.clone(), Action::Announce));
                    opt_new = new_iter.next();
                }
            }
        }

        items
    }

    /// Merges the content of two standard deltas into a new delta.
    fn merge(old: &Self, new: &Self) -> Self {
        let mut items = Self::default();

        let mut old_iter = old.items.iter();
        let mut new_iter = new.items.iter();

        let mut opt_old = old_iter.next();
        let mut opt_new = new_iter.next();

        loop {
            let old_item = match opt_old {
                Some(some) => some,
                None => {
                    // Old is finished. Keep everything from new.
                    if let Some(item) = opt_new {
                        items.push(item.clone())
                    }
                    items.extend(new_iter.cloned());
                    break;
                }
            };
            let new_item = match opt_new {
                Some(some) => some,
                None => {
                    // New is finished. Keep everything from old.
                    if let Some(item) = opt_old {
                        items.push(item.clone())
                    }
                    items.extend(old_iter.cloned());
                    break;
                }
            };

            match old_item.0.cmp(&new_item.0) {
                Ordering::Less => {
                    // Sole old item. Keep.
                    items.push(old_item.clone());
                    opt_old = old_iter.next();
                }
                Ordering::Greater => {
                    // Sole new item. Keep.
                    items.push(new_item.clone());
                    opt_new = new_iter.next();
                }
                Ordering::Equal => {
                    use rpki::rtr::payload::Action::*;

                    let action = match (old_item.1, new_item.1) {
                        (Announce, Announce) => Some(Announce),
                        (Announce, Withdraw) => None,
                        (Withdraw, Announce) => None,
                        (Withdraw, Withdraw) => Some(Withdraw)
                    };
                    if let Some(action) = action {
                        items.push((new_item.0.clone(), action));
                    }
                    opt_new = new_iter.next();
                    opt_old = old_iter.next();
                }
            }
        }

        items
    }
}

impl<P> StandardDelta<P> {
    /// Appends an item.
    fn push(&mut self, (payload, action): (P, Action)) {
        match action {
            Action::Announce => self.announce_len += 1,
            Action::Withdraw => self.withdraw_len += 1,
        }
        self.items.push((payload, action))
    }

    /// Appends all the items.
    fn extend(&mut self, iter: impl Iterator<Item = (P, Action)>) {
        iter.for_each(|item| self.push(item))
    }

    /// Returns whether this is an empty delta.
    ///
    /// A delta is empty if there is nothing announced and nothing withdrawn.
    fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Returns an element of the delta.
    fn get(&self, idx: usize) -> Option<(&P, Action)> {
        self.items.get(idx).map(|item| (&item.0, item.1))
    }
}


//------------ AspaDelta -----------------------------------------------------

/// A delta for ASPA payload.
#[derive(Clone, Debug, Default)]
struct AspaDelta {
    items: Vec<(Aspa, AspaAction)>,

    /// The number of annouced and updated items.
    announce_len: usize,

    /// The number of withdrawn items.
    withdraw_len: usize,
}

impl AspaDelta {
    fn construct<'a>(
        old_iter: impl Iterator<Item = (&'a Aspa, &'a PayloadInfo)>,
        new_iter: impl Iterator<Item = (&'a Aspa, &'a PayloadInfo)>,
    ) -> Self {
        use self::AspaAction::*;

        let mut items = Self::default();

        let mut old_iter = old_iter.map(|(item, _)| item);
        let mut new_iter = new_iter.map(|(item, _)| item);

        let mut opt_old = old_iter.next();
        let mut opt_new = new_iter.next();

        loop {
            let old_item = match opt_old {
                Some(item) => item,
                None => {
                    // Old is finished. The rest of new goes into announced.
                    if let Some(new_item) = opt_new {
                        items.push((new_item.clone(), Announce));
                    }
                    items.extend(new_iter.map(|x| {
                        (x.clone(), Announce)
                    }));
                    break;
                }
            };
            let new_item = match opt_new {
                Some(item) => item,
                None => {
                    // New is finished. The rest of old goes into withdraw.
                    items.push((old_item.withdraw(), Withdraw));
                    items.extend(
                        old_iter.map(|x| (x.withdraw(), Withdraw))
                    );
                    break;
                }
            };

            match old_item.key().cmp(&new_item.key()) {
                Ordering::Less => {
                    // Excess old item. Goes into withdraw.
                    items.push((old_item.withdraw(), Withdraw));
                    opt_old = old_iter.next();
                }
                Ordering::Equal => {
                    if old_item.providers != new_item.providers {
                        // Different providers. Goes into update.
                        items.push((new_item.clone(), Update))
                    }
                    opt_old = old_iter.next();
                    opt_new = new_iter.next();
                }
                Ordering::Greater => {
                    // Excess new item. Goes into announce.
                    items.push((new_item.clone(), Announce));
                    opt_new = new_iter.next();
                }
            }
        }

        items
    }

    /// Merges the content of two ASPA deltas into a new delta.
    fn merge(old: &Self, new: &Self) -> Self {
        let mut items = Self::default();

        let mut old_iter = old.items.iter();
        let mut new_iter = new.items.iter();

        let mut opt_old = old_iter.next();
        let mut opt_new = new_iter.next();

        loop {
            let old_item = match opt_old {
                Some(some) => some,
                None => {
                    // Old is finished. Keep everything from new.
                    if let Some(item) = opt_new {
                        items.push(item.clone())
                    }
                    items.extend(new_iter.cloned());
                    break;
                }
            };
            let new_item = match opt_new {
                Some(some) => some,
                None => {
                    // New is finished. Keep everything from old.
                    if let Some(item) = opt_old {
                        items.push(item.clone())
                    }
                    items.extend(old_iter.cloned());
                    break;
                }
            };

            match old_item.0.key().cmp(&new_item.0.key()) {
                Ordering::Less => {
                    // Sole old item. Keep.
                    items.push(old_item.clone());
                    opt_old = old_iter.next();
                }
                Ordering::Greater => {
                    // Sole new item. Keep.
                    items.push(new_item.clone());
                    opt_new = new_iter.next();
                }
                Ordering::Equal => {
                    use self::AspaAction::*;

                    // There are a few pairings that should be impossible,
                    // but I think we can fix the issue quitely ...
                    let action = match (old_item.1, new_item.1) {
                        (Announce, Announce) => Some(Announce),
                        (Announce, Update) => Some(Announce),
                        (Announce, Withdraw) => None,
                        (Update, Announce) => Some(Update),
                        (Update, Update) => Some(Update),
                        (Update, Withdraw) => Some(Withdraw),
                        (Withdraw, Announce) => Some(Update),
                        (Withdraw, Update) => Some(Update),
                        (Withdraw, Withdraw) => Some(Withdraw),
                    };
                    if let Some(action) = action {
                        items.push((new_item.0.clone(), action));
                    }
                    opt_old = old_iter.next();
                    opt_new = new_iter.next();
                }
            }
        }

        items
    }

    /// Appends an item.
    fn push(&mut self, (payload, action): (Aspa, AspaAction)) {
        match action {
            AspaAction::Announce | AspaAction::Update => self.announce_len += 1,
            AspaAction::Withdraw => self.withdraw_len += 1,
        }
        self.items.push((payload, action))
    }

    /// Appends all the items.
    fn extend(&mut self, iter: impl Iterator<Item = (Aspa, AspaAction)>) {
        iter.for_each(|item| self.push(item))
    }

    /// Returns whether this is an empty delta.
    ///
    /// A delta is empty if there is nothing announced and nothing withdrawn.
    fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Returns an element of the delta.
    fn get(&self, idx: usize) -> Option<(&Aspa, Action)> {
        self.items.get(idx).map(|item| (&item.0, item.1.into()))
    }
}


//----------- DeltaArcIter ---------------------------------------------------

/// An iterator over the elements of a shared delta.
#[derive(Clone, Debug)]
pub struct DeltaArcIter {
    /// The shared delta.
    delta: Arc<PayloadDelta>,

    /// The payload type we currently are processing.
    current_type: PayloadType,

    /// The index into the list of the payload type that is next to return.
    next: usize
}

impl DeltaArcIter {
    /// Creates a new iterator from a shared delta.
    fn new(delta: Arc<PayloadDelta>) -> Self {
        Self {
            delta,
            current_type: PayloadType::Origin,
            next: 0,
        }
    }
}

impl PayloadDiff for DeltaArcIter {
    fn next(&mut self) -> Option<(PayloadRef, Action)> {
        if matches!(self.current_type, PayloadType::Origin) {
            if let Some(res) = self.delta.origins.get(self.next) {
                self.next += 1;
                return Some((res.0.into(), res.1));
            }
            self.current_type = PayloadType::RouterKey;
            self.next = 0;
        }
        if matches!(self.current_type, PayloadType::RouterKey) {
            if let Some(res) = self.delta.router_keys.get(self.next) {
                self.next += 1;
                return Some((res.0.into(), res.1));
            }
            self.current_type = PayloadType::Aspa;
            self.next = 0;
        }
        assert!(matches!(self.current_type, PayloadType::Aspa));
        let res = self.delta.aspas.get(self.next)?;
        self.next += 1;
        Some((res.0.into(), res.1))
    }
}



//----------- AspaAction -----------------------------------------------------

/// A delta action for ASPA.
///
/// In ASPA ‘announce’ actually means both accounce a new ASPA or update an
/// existing one. In order to correctly merge two deltas, we need to know
/// which it really was.
#[derive(Clone, Copy, Debug)]
enum AspaAction {
    Announce,
    Update,
    Withdraw,
}

impl From<AspaAction> for Action {
    fn from(src: AspaAction) -> Self {
        match src {
            AspaAction::Announce => Action::Announce,
            AspaAction::Update => Action::Announce,
            AspaAction::Withdraw => Action::Withdraw,
        }
    }
}

