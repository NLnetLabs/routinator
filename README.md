# :rocket: Routinator 3000.

[![Travis Build Status](https://travis-ci.com/NLnetLabs/routinator.svg?branch=master)](https://travis-ci.com/NLnetLabs/routinator)

Introducing ‘Routinator 3000,’ an experimental RPKI relying party software
written in Rust. We are working towards a full production release over the
next few months. Features on the roadmap are:

  * [x] Fetch certificates and ROAs via rsync
  * [x] Perform crypotographic validation
  * [x] Export validated ROAs in CSV, JSON and RPSL format
  * [ ] Exhaustive interoperability and compliance testing
  * [ ] Implement the RPKI-RTR protocol for pushing RPKI data to supported routers ([RFC 6810](https://tools.ietf.org/html/rfc6810))
  * [ ] Implement the RRDP protocol for fetching ([RFC 8182](https://tools.ietf.org/html/rfc8182))
  * [ ] Add local exceptions and overrides
  * [ ] Implement a basic web-based user interface and Command Line Interface
  * [ ] Expose an API
  * [ ] Add the ability to process Internet Routing Registry data
  * [ ] Integration with alerting and monitoring services so that route hijacks, misconfigurations, connectivity and application problems can be flagged.


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
and macOS should be fine.

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


### C Toolchain

Some of the libraries Routinator depends on require a C toolchain to be
present. Your system probably has some easy way to install the minimum
set of packages to build from C sources. If you are unsure, try to run
`cc` on a command line and if there’s a complaint about missing input
files, you are probably good to go.


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
repository instances into `./rpki-cache/repository` and validate them.

When running, you might get rsync errors, such as from rpki.cnnic.cn.
You can ignore these. Certainly, Routinator will.

To get a better performance, build and run in release mode like so:

```bash
cargo run --release
```

It will then take forever to build but is quick to run, taking less than a
tenth (!) of the time for validation.

There is a number of command line options available. You can have cargo pass
them to the executable after a double hyphen. For instance, if to find out
about them, run

```bash
cargo run --release -- -h
```

When playing with these options, you might find `-n` useful. It will
cause Routinator to skip the rsync-ing of the repository – which should
be unnecessary if you re-run in quick succession.


## The Local Copy of the RPKI Repository

Routinator keeps a local copy of RPKI repository it collected for
validation. Its location can be specified with the `-c` command line
option. By default, this is the directory `rpki-cache` in the current
directory.

In there, Routinator expects to find the trust anchors in a sub-directory
called `tal`. Each file in that directory should be a Trust Anchor Locator
(TAL) as defined in RFC 7730.

The source repository contains an example of such an `rpki-cache` with the
current TALs of the five RIRs present. If you want to add additional trust
anchors, just drop their associated TAL files into that location.

