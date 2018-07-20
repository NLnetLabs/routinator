# A RPKI Relying Party in Rust

## Getting Started (aka What’s that Rust thing you keep going on about?)

If you don’t have it yet, you need Rust. There’s a tool called *rustup*
for that. If you feel lucky, simply do:

```bash
curl https://sh.rustup.rs -sSf | sh
```

or get the file, have a look and then run it manually. Follow the
instructions (if any) to get rustup and cargo, the rust build tool, into
your path.

If you already have Rust, make sure you have a reasonably new version. The
code assumes that you have the latest stable version. If in doubt, run

```bash
rustup update
```

## Building and Running

In the directory you cloned this repository to, say

```bash
cargo build
```

This will build the whole thing (or fail, of course). If it succeeds, you
can run

```bash
cargo run
```

to run the binary that has been built. At this point, it will rsync all
repository instances into `./rpki-cache/repository` and validate them. You
will need the `rsync` executable in your path.

To get a better performance, build and run in release mode like so:

```bash
cargo run --release
```

It will then take forever to build but is quick to run.

There is a number of command line options available. You can have cargo pass
them to the executable after a double hyphen. For instance, if to find out
about them, run

```bash
cargo run --relase -- -h
```
