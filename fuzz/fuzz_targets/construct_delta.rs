#![no_main]

use std::collections::{HashMap, HashSet};
use libfuzzer_sys::fuzz_target;
use routinator::payload::{PayloadDelta, PayloadSnapshot};
use rpki::rtr::{Action, Serial};
use rpki::rtr::payload::Aspa;
use rpki::rtr::pdu::ProviderAsns;

fuzz_target!{|data: (PayloadSnapshot, PayloadSnapshot, Serial)| {
    let (old, new, serial) = data;
    let delta = match PayloadDelta::construct(&old, &new, serial) {
        Some(delta) => {
            assert!(old.payload().ne(new.payload()));
            delta
        }
        None => {
            assert!(old.payload().eq(new.payload()));
            return;
        }
    };

    let old_origins: HashSet<_> = old.origins().map(|x| x.0).collect();
    let new_origins: HashSet<_> = new.origins().map(|x| x.0).collect();
    let delta_origins: Vec<_> = delta.origin_actions().collect();
    let mut set_origins: Vec<_> = new_origins.difference(
        &old_origins
    ).map(|x| (*x, Action::Announce)).chain(
        old_origins.difference(
            &new_origins
        ).map(|x| (*x, Action::Withdraw))
    ).collect();
    set_origins.sort();
    assert_eq!(delta_origins, set_origins);

    let old_keys: HashSet<_> = old.router_keys().map(|x| x.0).collect();
    let new_keys: HashSet<_> = new.router_keys().map(|x| x.0).collect();
    let delta_keys: Vec<_> = delta.router_key_actions().collect();
    let mut set_keys: Vec<_> = new_keys.difference(
        &old_keys
    ).map(|x| (*x, Action::Announce)).chain(
        old_keys.difference(
            &new_keys
        ).map(|x| (*x, Action::Withdraw))
    ).collect();
    set_keys.sort();
    assert_eq!(delta_keys, set_keys);

    let old_aspas: HashMap<_, _> = old.aspas().map(|x| {
        ((x.0.customer, x.0.afi), x.0.providers.clone())
    }).collect();
    let new_aspas: HashMap<_, _> = new.aspas().map(|x| {
        ((x.0.customer, x.0.afi), x.0.providers.clone())
    }).collect();
    let delta_aspas: Vec<_> = delta.aspa_actions().map(|x| (x.0.clone(), x.1)).collect();

    let mut set_aspas: Vec<_> = new_aspas.iter().filter_map(|(key, val)| {
        if let Some(old_val) = old_aspas.get(key) {
            if old_val == val {
                return None
            }
        }
        Some((Aspa::new(key.0, key.1, val.clone()), Action::Announce))
    }).chain(
        old_aspas.keys().filter_map(|key| {
            if !new_aspas.contains_key(key) {
                Some((
                    Aspa::new(key.0, key.1, ProviderAsns::empty()),
                    Action::Withdraw
                ))
            }
            else {
                None
            }
        })
    ).collect();
    set_aspas.sort();
    assert_eq!(delta_aspas, set_aspas);
}}
