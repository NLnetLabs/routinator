//! Changes between different version of payload.
//!
//! This is a private module. Its relevant public types are re-exported by
//! the parent.

use std::sync::Arc;
use std::cmp::Ordering;
use rpki::rtr::{Action, PayloadRef, PayloadType, Serial};
use rpki::rtr::payload::{Aspa, RouteOrigin, RouterKey};
use rpki::rtr::pdu::ProviderAsns;
use rpki::rtr::server::PayloadDiff;
use super::info::PayloadInfo;
use super::snapshot::PayloadSnapshot;


//------------ PayloadDelta --------------------------------------------------

/// The changes between two payload snapshots.
///
/// You can create a delta from two snapshots through the
/// [`Self::construct`] function or by merging two existing deltas via
/// [`merge`][Self::merge].
///
/// An existing delta allows you to iterate over its contents – called
/// actions – in various ways, both for all actions or only those regarding
/// a particular payload type.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
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
    /// The argument `serial` constains the serial number of the old
    /// snapshot, i.e., the current serial number of the payload history.
    ///
    /// Returns `None` if the two snapshots are, in fact, identical.
    pub fn construct(
        old: &PayloadSnapshot, new: &PayloadSnapshot, serial: Serial,
    ) -> Option<Self> {
        let res = Self {
            serial: serial.add(1),
            origins: StandardDelta::construct(
                old.origin_refs().map(|item| item.0),
                new.origin_refs().map(|item| item.0),
            ),
            router_keys: StandardDelta::construct(
                old.router_keys().map(|item| item.0),
                new.router_keys().map(|item| item.0),
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

    /// Returns an iterator over the actions on route origins.
    pub fn origin_actions(
        &self
    ) -> impl Iterator<Item = (RouteOrigin, Action)> + '_ {
        self.origins.items.iter().map(|(item, action)| (*item, *action))
    }

    /// Returns an iterator over the actions on router keys.
    pub fn router_key_actions(
        &self
    ) -> impl Iterator<Item = (&RouterKey, Action)> + '_ {
        self.router_keys.items.iter().map(|(item, action)| (item, *action))
    }

    /// Returns an iterator over the actions on ASPAs. 
    pub fn aspa_actions(
        &self
    ) -> impl Iterator<Item = (&Aspa, Action)> + '_ {
        self.aspas.items.iter().map(|(item, action)| (item, action.into()))
    }

    /// Returns an iterator over the actions.
    pub fn actions(
        &self
    ) -> impl Iterator<Item = (PayloadRef, Action)> + '_ {
        self.origin_actions().map(|(p, a)| (p.into(), a)).chain(
            self.router_key_actions().map(|(p, a)| (p.into(), a))
        ).chain(
            self.aspa_actions().map(|(p, a)| (p.into(), a))
        )
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

    /// The number of announced items.
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
    /// Construct a delta from iterators over old and new content.
    fn construct<'a>(
        mut old_iter: impl Iterator<Item = &'a P>,
        mut new_iter: impl Iterator<Item = &'a P>,
    ) -> Self
    where P: 'a {
        let mut items = Self::default();

        let mut opt_old = old_iter.next();
        let mut opt_new = new_iter.next();

        loop {
            let old_item = match opt_old {
                Some(item) => item,
                None => {
                    // Old is finished. The rest of new goes into announced.
                    if let Some(new_item) = opt_new {
                        items.push((new_item.clone(), Action::Announce));
                    }
                    items.extend(
                        new_iter.map(|x| (x.clone(), Action::Announce))
                    );
                    break;
                }
            };
            let new_item = match opt_new {
                Some(item) => item,
                None => {
                    // New is finished. The rest of old goes into withdraw.
                    items.push((old_item.clone(), Action::Withdraw));
                    items.extend(
                        old_iter.map(|x| (x.clone(), Action::Withdraw))
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

#[cfg(feature = "arbitrary")]
impl<'a, P> arbitrary::Arbitrary<'a> for StandardDelta<P>
where P: arbitrary::Arbitrary<'a> + Ord {
    fn arbitrary(
        u: &mut arbitrary::Unstructured<'a>
    ) -> arbitrary::Result<Self> {
        let mut items = Vec::<(P, Action)>::arbitrary(u)?;
        items.sort_by(|left, right| left.0.cmp(&right.0));
        items.dedup_by(|left, right| left.0 == right.0);
        let announce_len = items.iter().filter(|(_, action)| {
            matches!(action, Action::Announce)
        }).count();
        let withdraw_len = items.iter().filter(|(_, action)| {
            matches!(action, Action::Withdraw)
        }).count();
        Ok(Self { items, announce_len, withdraw_len })
    }
}


//------------ AspaDelta -----------------------------------------------------

/// A delta for ASPA payload.
///
/// Deltas for ASPAs are a bit complicated because the set of ASPAs is
/// actually a map assigning the provider ASN set to a key of the pair of
/// customer ASN and address family (‘AFI’). The ‘announce’ action of a delta
/// between two of those maps covers both adding a new key and updating the
/// provider set of an existing key.
///
/// This makes it necessary to keep additional information for correctly
/// merging deltas. These are kept in the [`AspaAction`] enum.
#[derive(Clone, Debug, Default)]
struct AspaDelta {
    /// The items of the delta.
    items: Vec<(Aspa, AspaAction)>,

    /// The number of announced and updated items.
    announce_len: usize,

    /// The number of withdrawn items.
    withdraw_len: usize,
}

impl AspaDelta {
    /// Constructs a new delta from iterators over old and new payload.
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
                    items.push(AspaAction::withdraw(old_item));
                    items.extend(old_iter.map(AspaAction::withdraw));
                    break;
                }
            };

            match old_item.key().cmp(&new_item.key()) {
                Ordering::Less => {
                    // Excess old item. Goes into withdraw.
                    items.push(AspaAction::withdraw(old_item));
                    opt_old = old_iter.next();
                }
                Ordering::Equal => {
                    if old_item.providers != new_item.providers {
                        // Different providers. Goes into update.
                        items.push((
                            new_item.clone(),
                            Update(old_item.providers.clone())
                        ))
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
                    // Old is finished. Keep all changes made by new.
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
                    // New is finished. Keep all changes made by old.
                    if let Some(item) = opt_old {
                        items.push(item.clone())
                    }
                    items.extend(old_iter.cloned());
                    break;
                }
            };

            // Compare ASPAs only by their key.
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

                    // The item is both in old and new. What to do depends
                    // on the two actions.
                    let action = match (&old_item.1, &new_item.1) {
                        // Announced in both deltas. Technically that can’t
                        // happen, but we just pretend it was announced.
                        (Announce, Announce) => Some(Announce),

                        // Announced then updated: just announced.
                        (Announce, Update(_)) => Some(Announce),

                        // Announced then withdrawn: never happened.
                        (Announce, Withdraw(_)) => None,

                        // Updated then announced. Can’t really happen but we
                        // pretend it was updated from the original providers.
                        (Update(ref p), Announce) => Some(Update(p.clone())),

                        // Updated twice. If the new providers are equal to
                        // the original providers, nothing happened. Otherwise
                        // it is an update.
                        (Update(ref p), Update(_)) => {
                            if *p == new_item.0.providers {
                                None
                            }
                            else {
                                Some(Update(p.clone()))
                            }
                        }

                        // Updated then withdrawn: withdrawn.
                        (Update(ref p), Withdraw(_)) => {
                            Some(Withdraw(p.clone()))
                        }

                        // Withdrawn then announced. If the new providers are
                        // equal to the original providers, nothing happened.
                        // Otherwise, this is an update.
                        (Withdraw(ref p), Announce) => {
                            if *p == new_item.0.providers {
                                None
                            }
                            else {
                                Some(Update(p.clone()))
                            }
                        }

                        // Withdraw then updated. Can’t happen, but we treat
                        // the update as an announce.
                        (Withdraw(ref p), Update(_)) => {
                            if *p == new_item.0.providers {
                                None
                            }
                            else {
                                Some(Update(p.clone()))
                            }
                        }

                        // Withdrawn twice. Can’t happen but whatever.
                        (Withdraw(ref p), Withdraw(_)) => {
                            Some(Withdraw(p.clone()))
                        }
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
            AspaAction::Announce | AspaAction::Update(_) => {
                self.announce_len += 1
            }
            AspaAction::Withdraw(_) => self.withdraw_len += 1,
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
        self.items.get(idx).map(|item| (&item.0, (&item.1).into()))
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for AspaDelta {
    fn arbitrary(
        u: &mut arbitrary::Unstructured<'a>
    ) -> arbitrary::Result<Self> {
        let mut items = Vec::<(Aspa, AspaAction)>::arbitrary(u)?;
        items.sort_by(|left, right| left.0.cmp(&right.0));
        items.dedup_by(|left, right| left.0 == right.0);
        let announce_len = items.iter().filter(|(_, action)| {
            matches!(action, AspaAction::Announce | AspaAction::Update(_))
        }).count();
        let withdraw_len = items.iter().filter(|(_, action)| {
            matches!(action, AspaAction::Withdraw(_))
        }).count();
        Ok(Self { items, announce_len, withdraw_len })
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
/// This type contains all the extra information necessary for merging
/// [`AspaDelta`]s.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
enum AspaAction {
    /// Announce an ASPA for a new key.
    ///
    /// This simply becomes `Action::Announce`.
    Announce,

    /// Update the providers of an existing key.
    ///
    /// This becomes `Action::Announce`.
    ///
    /// The value is the providers before the update.
    Update(ProviderAsns),

    /// Withdraw the ASPA for a key.
    ///
    /// This becomes `Action::Withdraw`.
    ///
    /// The value is the providers before the key was withdrawn.
    Withdraw(ProviderAsns),
}

impl AspaAction {
    fn withdraw(aspa: &Aspa) -> (Aspa, Self) {
        (aspa.withdraw(), Self::Withdraw(aspa.providers.clone()))
    }
}

impl From<AspaAction> for Action {
    fn from(src: AspaAction) -> Self {
        match src {
            AspaAction::Announce => Action::Announce,
            AspaAction::Update(_) => Action::Announce,
            AspaAction::Withdraw(_) => Action::Withdraw,
        }
    }
}

impl<'a> From<&'a AspaAction> for Action {
    fn from(src: &'a AspaAction) -> Self {
        match *src {
            AspaAction::Announce => Action::Announce,
            AspaAction::Update(_) => Action::Announce,
            AspaAction::Withdraw(_) => Action::Withdraw,
        }
    }
}


//============ Tests =========================================================

#[cfg(test)]
mod test {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn standard_construct() {
        fn process(old: &mut [u32], new: &mut [u32]) {
            let old_set: HashSet<_> = old.iter().copied().collect();
            let new_set: HashSet<_> = new.iter().copied().collect();
            old.sort();
            new.sort();
            let delta = StandardDelta::construct(old.iter(), new.iter());

            let mut announce_set: Vec<_> = new_set.difference(
                &old_set
            ).copied().collect();
            announce_set.sort();
            let announce = delta.items.iter().filter_map(|(item, action)| {
                match action {
                    Action::Announce => Some(*item),
                    Action::Withdraw => None
                }
            }).collect::<Vec<_>>();

            let mut withdraw_set: Vec<_> = old_set.difference(
                &new_set
            ).copied().collect();
            withdraw_set.sort();
            let withdraw = delta.items.iter().filter_map(|(item, action)| {
                match action {
                    Action::Withdraw => Some(*item),
                    Action::Announce => None,
                }
            }).collect::<Vec<_>>();

            assert_eq!(announce.len(), delta.announce_len);
            assert_eq!(withdraw.len(), delta.withdraw_len);
            assert_eq!(announce, announce_set);
            assert_eq!(withdraw, withdraw_set);
        }

        process(&mut [], &mut []);
        process(&mut [0, 1, 2, 3], &mut [0, 1, 2, 3]);
        process(&mut [], &mut [0, 1, 2, 3]);
        process(&mut [0, 1, 2, 3], &mut []);

        // 1 item difference
        process(&mut [0,    2, 3], &mut [0, 1, 2, 3]);
        process(&mut [0, 1, 2, 3], &mut [0,    2, 3]);
        process(&mut [   1, 2, 3], &mut [0, 1, 2, 3]);
        process(&mut [0, 1, 2, 3], &mut [   1, 2, 3]);
        process(&mut [0, 1, 2   ], &mut [0, 1, 2, 3]);
        process(&mut [0, 1, 2, 3], &mut [0, 1, 2   ]);

        // 2 item difference
        process(&mut [0, 1, 2, 3], &mut [0, 1, 2, 3]);
        process(&mut [0,       3], &mut [0, 1, 2, 3]);
        process(&mut [0, 1, 2, 3], &mut [0,       3]);
        process(&mut [      2, 3], &mut [0, 1, 2, 3]);
        process(&mut [0, 1, 2, 3], &mut [      2, 3]);
        process(&mut [0, 1,     ], &mut [0, 1, 2, 3]);
        process(&mut [0, 1, 2, 3], &mut [0, 1,     ]);
    }

    // Delta merging has been tested via the merge_deltas fuzz target.
}

