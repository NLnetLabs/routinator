# Routinator 3000.

Introducing ‘Routinator 3000,’ an experimental RPKI relying party software
written in Rust.


## RPKI

The Resource Public Key Infrastructure provides cryptographically signed
statements about the association of Internet routing resources. In
particular, it allows the holder of an IP address prefix to publish which
AS number will be the origin of BGP route announcements for it.

All of these statements are published in a distributed repository. The
Routinator 3000 will collect these statements into a local copy, validate
their signatures, and output a list of associations between IP address
prefixes and AS numbers in a number of useful formats.


## Getting Started

There’s two things you need for the Routinator: rsync and Rust. You need
the former because the RPKI repository currently uses rsync as its main
means of distribution. You need the latter because that’s what the
Routinator has been written in. Since this currently is a very early
experimental version, we decided not to distribute binary packages just
yet. But don’t worry, getting Rust and building packages with it is easy.


### rsync

Currently, Routinator requires the `rsync` executable to be in your path.
We are not quite sure which particular version you need at the very least,
but whatever is being shipped with current Linux and \*BSD distributions
and macOS.

If you don’t have rsync, please head to http://rsync.samba.org/.


### Rust

The easiest and canonical way to install Rust on your machine and maintain
that installation is a tool called *rustup.* While some distributions
include Rust packages, we kind of rely on very recent stable releases at
this point, so using rustup is preferred.

If you feel lucky, simply do:

```bash
curl https://sh.rustup.rs -sSf | sh
```

or, alternatively, get the file, have a look and then run it manually.
Follow the instructions to get rustup and cargo, the rust build tool, into
your path.

You can update your Rust installation later by simply running

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

