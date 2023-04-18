#![no_main]

use libfuzzer_sys::fuzz_target;
use routinator::payload::{PayloadDelta, PayloadSnapshot};

const N: usize = 10;

fuzz_target!{|data: [PayloadSnapshot; N]| {
    let mut steps = Vec::new();
    for i in 0..N - 1 {
        if let Some(delta) = PayloadDelta::construct(
            &data[i], &data[i + 1], 1.into()
        ) {
            steps.push(delta);
        }
    }

    let full = PayloadDelta::construct(
        &data[0], &data[N - 1], 1.into()
    ).unwrap_or_else(|| PayloadDelta::empty(1.into()));

    if steps.is_empty() {
        assert!(full.is_empty());
        return
    }

    let mut steps = steps.into_iter();
    let mut merged = steps.next().unwrap();
    while let Some(delta) = steps.next() {
        merged = merged.merge(&delta);
    }

    let merged = merged.actions().collect::<Vec<_>>();
    let full = full.actions().collect::<Vec<_>>();

    assert_eq!(merged, full)
}}

