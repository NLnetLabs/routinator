
#[cfg(feature = "extra-debug")]
macro_rules! xdebug {
    () => (eprint!("\n"));
    ($fmt:expr) => (eprint!(concat!($fmt, "\n")));
    ($fmt:expr, $($arg:tt)*) => (eprint!(concat!($fmt, "\n"), $($arg)*));
}

#[cfg(feature = "extra-debug")]
macro_rules! xerr {
    ($test:expr, $msg:expr) => (
        $test.map_err(|err| {
            xdebug!("{}: {:?}", $msg, err);
            err
        })
    )
}

#[cfg(not(feature = "extra-debug"))]
macro_rules! xdebug {
    () => ();
    ($fmt:expr) => ();
    ($fmt:expr, $($arg:tt)*) => ();
}

#[cfg(not(feature = "extra-debug"))]
macro_rules! xerr {
    ($test:expr, $msg:expr) => ( $test )
}

