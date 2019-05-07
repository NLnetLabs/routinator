# Routinator

[![Travis Build Status](https://travis-ci.com/NLnetLabs/routinator.svg?branch=master)](https://travis-ci.com/NLnetLabs/routinator)
[![AppVeyor Build
Status](https://ci.appveyor.com/api/projects/status/github/NLnetLabs/routinator?svg=true)](https://ci.appveyor.com/project/partim/routinator)
[![](https://img.shields.io/docker/build/nlnetlabs/routinator.svg)](https://hub.docker.com/r/nlnetlabs/routinator)
[![](https://img.shields.io/crates/v/routinator.svg)](https://crates.io/crates/routinator)
[![Documentation Status](https://readthedocs.org/projects/rpki/badge/?version=latest)](https://rpki.readthedocs.io/en/latest/?badge=latest)
[![](https://img.shields.io/badge/Spotify-∞-green.svg)](https://open.spotify.com/user/alex.band/playlist/1DkYwN4e4tq73LGAeUykA1?si=AXNn9GkpQ4a-q5skG1yiYQ)
[![](https://img.shields.io/twitter/follow/routinator3000.svg?label=Follow&style=social)](https://twitter.com/routinator3000)

Introducing ‘Routinator 3000,’ RPKI relying party software written in Rust.
If you have any feedback, we would love to hear from you. Don’t hesitate to
[create an issue on Github](https://github.com/NLnetLabs/routinator/issues/new)
or post a message on our [RPKI mailing list](https://nlnetlabs.nl/mailman/listinfo/rpki).
You can lean more about Routinator and RPKI technology by reading our documentation on
[Read the Docs](https://rpki.readthedocs.io/).

## Quick Start

Assuming you have rsync and the C toolchain but not yet [Rust 1.34](#rust) 
or newer, here’s how you get the Routinator to run as an RTR server listening 
on 127.0.0.1 port 3323:

```bash
curl https://sh.rustup.rs -sSf | sh
source ~/.cargo/env
cargo install routinator
routinator rtrd -al 127.0.0.1:3323
```

If you have an older version of the Routinator, you can update via

```bash
cargo install -f routinator
```

## Quick Start with Docker

Due to the impracticality of complying with the ARIN TAL distribution terms
in an unsupervised Docker environment, prior to launching the container it
is necessary to first review and agree to the ARIN TAL terms available at
https://www.arin.net/resources/rpki/tal.html

The ARIN TAL RFC 7730 format file available at that URL will then need to
be downloaded and mounted into the docker container as a replacement for
the dummy arin.tal file that is shipped with Routinator.

```bash
# Create a local directory for the RPKI cache
sudo mkdir -p /etc/routinator/tals
# Fetch the ARIN TAL (after agreeing to the distribution terms as described above)
sudo wget https://www.arin.net/resources/manage/rpki/arin-rfc7730.tal -P /etc/routinator/tals
# Launch a detached container named 'routinator' (will listen on 0.0.0.0:3323 and expose that port)
sudo docker run -d --name routinator -p 3323:3323 -v /etc/routinator/tals/arin-rfc7730.tal:/root/.rpki-cache/tals/arin.tal nlnetlabs/routinator
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
      supported routers ([RFC 6810](https://tools.ietf.org/html/rfc6810), [RFC 8210](https://tools.ietf.org/html/rfc8210))
* [x] Monitoring endpoint (Prometheus)    
* [ ] Exhaustive interoperability and compliance testing
* [ ] Integration with alerting and monitoring services so that route
      hijacks, misconfigurations, connectivity and application problems
      can be flagged.
* [ ] Implement the RRDP protocol for fetching
      ([RFC 8182](https://tools.ietf.org/html/rfc8182))
* [ ] Implement a basic web-based user interface and Command Line Interface
* [ ] Expose an API
* [ ] Add the ability to process Internet Routing Registry data

## System Requirements

Routinator is designed to be lean and is capable of running on minimalist
hardware, such as a Raspberry Pi. Running it on a system with 1GB of 
available RAM and 1GB of available disk space will give the global RPKI
data set enough room to grow for the forseeable future. A powerful CPU is
not required, as cryptographic validation currently takes less than two 
seconds on an average system.

## Getting Started

There’s two things you need for Routinator: rsync and Rust and a C toolc…
There are three things you need for Routinator: rsync, a C toolchain and 
Rust. You need rsync because the RPKI repository currently uses rsync
as its main means of distribution. Some of the cryptographic primitives 
used by the Routinator require a C toolchain, so you need that, too. You 
need Rust because that’s what Routinator has been written in. 

Since this currently is an early version, we decided not to distribute
binary packages just yet. But don’t worry, getting Rust and building
packages with it is easy.

### rsync

Currently, Routinator requires the `rsync` executable to be in your path.
We are not quite sure which particular version you need at the very least,
but whatever is being shipped with current Linux and \*BSD distributions
and macOS should be fine.

On Windows, Routinator requires the `rsync` version that comes with
[Cygwin](https://www.cygwin.com/) – make sure to select rsync during the
installation phase. And yes, Routinator totally works on Windows, too.

If you don’t have rsync, please head to http://rsync.samba.org/

### C Toolchain

Some of the libraries Routinator depends on require a C toolchain to be
present. Your system probably has some easy way to install the minimum
set of packages to build from C sources. If you are unsure, try to run
`cc` on a command line and if there’s a complaint about missing input
files, you are probably good to go.

On some older systems, the toolchain may not be up-to-date enough. We
are collecting information as it comes up in a
[separate document](doc/misc.md). One such instance is
[CentOS 6](doc/misc.md#building-on-centos-6).

### Rust

The Rust compiler runs on, and compiles to, a great number of platforms.
The official [Rust Platform Support](https://forge.rust-lang.org/platform-support.html)
page provides an overview of the various platforms and support levels.

While some system distributions include Rust as system packages, 
Routinator relies on a relatively new version of Rust, currently 1.34 or 
newer. We therefore suggest to use the canonical Rust installation via a
tool called ``rustup``.

To install ``rustup`` and Rust, simply do:

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

The easiest way to get Routinator is to leave it to cargo by saying

```bash
cargo install routinator
```

If you want to try the master branch from the repository instead of a
release version, you can run

```bash
cargo install --git https://github.com/NLnetLabs/routinator.git
```

If you want to update an installed version, you run the same command but
add the `-f` flag (aka force) to approve overwriting the installed
version.

The command will build Routinator and install it in the same directory
that cargo itself lives in (likely `$HOME/.cargo/bin`).
Which means Routinator will be in your path, too.

There are currently two major functions of the Routinator: printing the
list of valid route origins, also known as _Validated ROA Payload_ or VRP,
and providing the service for routers to access this list via a protocol
known as RPKI-to-Router protocol or RTR.

These (and all other functions) of Routinator are accessible on the
command line via sub-commands. The commands are `vrps` and `rtrd`,
respectively.

So, to have Routinator print the list, you say

```bash
routinator vrps
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

Information about additional command line arguments is available via the
`-h` option or you can look at the more detailed man page via the `man`
sub-command:

```bash
routinator man
```

It is also available online on the
[NLnetLabs documentation site](https://www.nlnetlabs.nl/documentation/rpki/routinator/).

## Feeding a Router with RPKI-RTR

Routinator supports RPKI-RTR as specified in RFC 8210 as well as the older
version from RFC 6810. It will act as an RTR server if you start it with
the `rtrd` sub-command. It will do so as a daemon and detach from your
terminal unless you provide the `-a` (for attached) option.

You can specify the address(es) to listen on via the `-l` (or `--listen`)
option. If you don’t, it will listen on `127.0.0.1:3323` by default. This
isn’t the IANA-assigned default port for the protocol, which would be 323.
But since that is a privileged port you’d need to be running Routinator as
root when otherwise there is no reason to do that. Also, note that the
default address is a localhost address for security reasons.

So, in order to run Routinator as an RTR server listening on port 3323 on
both 192.0.2.13 and 2001:0DB8::13 without detaching from the terminal, run

```bash
routinator rtrd -a -l 192.0.2.13:3323 -l [2001:0DB8::13]:3323
```

By default, the repository will be updated and re-validated every hour as
per the recommendation in the RFC. You can change this via the
`--refresh` option and specify the interval between re-validations in
seconds. That is, if you rather have Routinator validate every fifteen
minutes, the above command becomes

```bash
routinator rtrd -a -l 192.0.2.13:3323 -l [2001:0DB8::13]:3323 --refresh=900
```

## Secure Transports for RPKI-RTR

[RFC6810](https://tools.ietf.org/html/rfc6810#page-17) defines a number of
secure transports for RPKI-RTR that can be used for communication between
a router and a RPKI relying party.

Documentation on configuring secure transports with Routinator can be
found [here](doc/transports.md).

## Configuration Files

Routinator can take its configuration from a file, too. You can specify
such a configuration file via the `-c` option. If you don’t, Routinator
will check if there is a file `$HOME/.routinator.conf` and if it exists,
use it. If it doesn’t exist and there is no `-c` option, default values
are used.

The configuration file is a TOML file. Its entries are named similarly to
the command line options. Details about the available entries and there
meaning can be found in the manual page. In addition, a complete sample
configuration file showing all the default values can be found in the
repository at [etc/routinator.conf](https://github.com/NLnetLabs/routinator/blob/master/etc/routinator.conf).

## Local Exceptions

If you would like to add exceptions to the validated RPKI data in the
form of local filters and additions, you can specify this in a file
using JSON notation according to the [SLURM] standard. You can find
two example files in the repository at `/test/slurm`. Use the `-x` option
to refer to your file with local exceptions.

Routinator will re-read that file on every validation run, so you can
simply update the file whenever your exceptions change.

## Monitoring

Monitoring a Routinator instance is possible by enabling the integrated
[Prometheus](https://prometheus.io/) exporter using the `listen-http`
configuration option or command line parameter.

Port [9556](https://github.com/prometheus/prometheus/wiki/Default-port-allocations)
is allocated for this use. A Routinator instance with monitoring on this
port can be launched so:

```bash
routinator rtrd -a -l 192.0.2.13:3323 -l [2001:0DB8::13]:3323 --listen-http 192.0.2.13:9556
```

[SLURM]: https://tools.ietf.org/html/rfc8416
