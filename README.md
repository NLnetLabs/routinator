# :rocket: Routinator

[![Travis Build Status](https://travis-ci.com/NLnetLabs/routinator.svg?branch=master)](https://travis-ci.com/NLnetLabs/routinator)

Introducing ‘Routinator 3000,’ RPKI relying party software written in Rust.

Even though it is still early days for the Routinator, we have decided to
provide a release in the spirit of open development. Please consider this
when using the software. If you have any feedback, we would love to hear
from you. Don’t hesitate to 
[create an issue of Github](https://github.com/NLnetLabs/routinator/issues/new)
or drop us a line a [rpki@nlnetlabs.nl](mailto:rpki@nlnetlabs.nl).


## Quick Start

Assuming you have rsync and the C toolchain but not yet Rust, here’s how
you get the Routinator to run as an RTR server listening on 127.0.0.1 port
3323:

```
curl https://sh.rustup.rs -sSf | sh
source ~/.cargo/env
cargo install routinator
routinator -r -l 127.0.0.1:3323
```


## RPKI

The Resource Public Key Infrastructure provides cryptographically signed
statements about the association of Internet routing resources. In
particular, it allows the holder of an IP address prefix to publish which
AS number will be the origin of BGP route announcements for it.

All of these statements are published in a distributed repository. 
Routinator will collect these statements into a local copy, validate
their signatures, and construct a list of associations between IP address
prefixes and AS numbers. It provides this information to routers supporting
the RPKI-RTR protocol or can output it in a number of useful formats. 


## Full Roadmap

  * [x] Fetch certificates and ROAs via rsync
  * [x] Perform cryptographic validation
  * [x] Export validated ROAs in CSV, JSON and RPSL format
  * [x] Add local white list exceptions and overrides
        ([RFC 8416](https://tools.ietf.org/html/rfc8416))
  * [x] Implement the RPKI-RTR protocol for pushing RPKI data to
        supported routers ([RFC 6810](https://tools.ietf.org/html/rfc6810))
  * [ ] Exhaustive interoperability and compliance testing
  * [ ] Implement the RRDP protocol for fetching
        ([RFC 8182](https://tools.ietf.org/html/rfc8182))
  * [ ] Implement a basic web-based user interface and Command Line Interface
  * [ ] Expose an API
  * [ ] Add the ability to process Internet Routing Registry data
  * [ ] Integration with alerting and monitoring services so that route
        hijacks, misconfigurations, connectivity and application problems
        can be flagged.


## Getting Started

There’s two things you need for Routinator: rsync and Rust and a C toolc…
There is three things you need for Routinator: rsync, Rust and a C
toolchain. You need rsync because the RPKI repository currently uses rsync
as its main means of distribution. You need Rust because that’s what the
Routinator has been written in. Some of the cryptographic primitives used
by the Routinator require a C toolchain, so you need that, too.

Since this currently is a very early
experimental version, we decided not to distribute binary packages just
yet. But don’t worry, getting Rust and building packages with it is easy.


### rsync

Currently, Routinator requires the `rsync` executable to be in your path.
We are not quite sure which particular version you need at the very least,
but whatever is being shipped with current Linux and \*BSD distributions
and macOS should be fine.

If you don’t have rsync, please head to http://rsync.samba.org/.


### Rust

While some system distributions include Rust as system packages,
Routinator relies on a relatively new version of Rust, currently 1.29 or
newer. We therefore suggest to use the canonical Rust installation via a
tool called *rustup.*

To install *rustup* and Rust, simply do:

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

The easiest way to get Routinator is to leave it to cargo by saying

```
cargo install routinator
```

This will build Routinator and install it in the same directory that cargo
itself lives in (likely `$HOME/.cargo/bin`). Which means that you can run
routinator simply as:

```bash
routinator
```

If this is the first time you’ve
been using Routinator, it will create `$HOME/.rpki-cache`, put the
trust anchor locators of the five RIRs there, and then complain that
ARIN’s TAL is in fact not really there.

Follow the instructions provided and try again. You can also add
additional trust anchors by simple dropping their TAL file in RFC 7730
format into `$HOME/.rpki-cache/tals`.

Now Routinator will rsync the entire RPKI repository to your machine
(which will take a while during the first run), validate it and produce
a long list of AS numbers and prefixes.

When running, you might get rsync errors, such as from rpki.cnnic.cn
which isn’t reachable. These servers will be ignored and tried again on
the next run, so you ignore the errors.

There are a number of command line options available. You can  find out
about them by running

```bash
routinator -h
```

For somewhat more complete information on the options, you can also
consult the man page. It lives in `doc/routinator.1` in the repository but
is also included in the executable and accessible via the `--man` option.
On Linux, you can simply run:

```bash
routinator --man | man -l -
```

It is also available online on the
[NLnetLabs documentation
site](https://www.nlnetlabs.nl/documentation/rpki/routinator/).


## Feeding a Router with RPKI-RTR

Routinator supports RPKI-RTR as specified in RFC 8210. It will act as an
RTR server if you start it with the `-r` (or `--repeat`) or `-d`
(`--daemon`) option. In the latter case it will detach from the terminal
and log to syslog while in repeat mode it’ll stay with you.

You can specify the address(es) to listen on via the `-l` (or `--listen`)
option. If you don’t, it will listen on `127.0.0.1:3323` by default. We
are not using the IANA-assigned default port RTR, port 323, because that
would require root permissions to bind to the port. Also, note that the
default address is a localhost address for security reasons.

So, in order to run Routinator as an RTR server listening on port 3323 on
both 192.0.2.13 and 2001:0DB8::13 in repeat mode, execute

```bash
routinator -r -l 192.0.2.13:3323 -l [2001:0DB8::13]:3323
```

By default, the repository will be updated and re-validated every hour as
per the recommendation in the RFC. You can change this via the
``--refresh` option and specify the intervall between re-validations in
seconds. That is, if you rather have Routinator validate every fifteen
minutes, the above command becomes

```bash
routinator -r -l 192.0.2.13:3323 -l [2001:0DB8::13]:3323 --refresh=900
```


## Local Exceptions

If you would like to add exceptions to the validated RPKI data in the 
form of local filters and additions, you can specify this in a file 
using JSON notation according to the [SLURM] standard. You can find 
two example files in the repository at `/test/slurm`. Use the `-x` option
to refer to your file with local exceptions.

Routinator will re-read that file on every validation run, so you can
simply update the file whenever your exceptions change.

[SLURM]: https://tools.ietf.org/html/rfc8416

