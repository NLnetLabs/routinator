#[cfg(feature = "extra-debug")]
#[allow(unused_macros)]
macro_rules! xerr {
    ($test:expr) => { panic!("extra debugging enabled") };
}

#[cfg(not(feature = "extra-debug"))]
#[allow(unused_macros)]
macro_rules! xerr {
    ($test:expr) => { $test };
}

