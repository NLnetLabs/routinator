# Routinator

<img align="right" src="https://www.nlnetlabs.nl/static/logos/Routinator/Routinator_Avatar_Realistic.svg" height="150">

[![crates.io](https://img.shields.io/crates/v/routinator.svg?color=brightgreen)](https://crates.io/crates/routinator)
[![CI](https://github.com/NLnetLabs/routinator/workflows/ci/badge.svg)](https://github.com/NLnetLabs/routinator/actions?query=workflow%3Aci)
[![Packaging](https://github.com/NLnetLabs/routinator/actions/workflows/pkg.yml/badge.svg)](https://nlnetlabs.nl/packages/)
[![Docker Pulls](https://img.shields.io/docker/pulls/nlnetlabs/routinator?color=brightgreen)](https://hub.docker.com/r/nlnetlabs/routinator)
[![Documentation Status](https://readthedocs.org/projects/routinator/badge/?version=stable)](https://routinator.docs.nlnetlabs.nl/en/stable/)

[![Spotify](https://img.shields.io/badge/Spotify-∞-brightgreen.svg)](https://open.spotify.com/user/alex.band/playlist/1DkYwN4e4tq73LGAeUykA1?si=AXNn9GkpQ4a-q5skG1yiYQ)
[![Discord](https://img.shields.io/discord/818584154278199396?label=Discord&logo=discord)](https://discord.gg/8dvKB5Ykhy)
[![Mastodon Follow](https://img.shields.io/mastodon/follow/109262826617293067?domain=https%3A%2F%2Ffosstodon.org&style=social)](https://fosstodon.org/@nlnetlabs)
[![Twitter](https://img.shields.io/twitter/follow/routinator3000.svg?label=Follow&style=social)](https://twitter.com/routinator3000)

Routinator 3000 is free, open-source RPKI Relying Party software. The project
is written in Rust, a programming language designed for performance and
memory safety.

### Lightweight and portable

Routinator has minimal system requirements and it can run on almost any
hardware and platform, with packages available for most. You can also easily
run with Docker or Cargo, the Rust package manager.

### Full-featured and secure

Routinator runs as a service that periodically downloads and verifies RPKI
data. The built-in HTTPS server offers a user interface, API endpoints for
various file formats, as well as logging, status and Prometheus metrics.

### Flexible RPKI-to-Router (RTR) support

Routinator has a built-in RTR server to let routers fetch verified RPKI data.
You can also run RTR as a separate daemon using our RPKI data proxy
[RTRTR](https://www.nlnetlabs.nl/projects/rpki/rtrtr/), letting you
centralise validation and securely distribute processed data to various
locations.

### Open-source with professional support services

NLnet Labs offers [professional support and consultancy
services](https://www.nlnetlabs.nl/services/contracts/) with a service-level
agreement. Community support is available on
[Discord](https://discord.gg/8dvKB5Ykhy),
[Twitter](https://twitter.com/routinator3000/) and our [mailing
list](https://lists.nlnetlabs.nl/mailman/listinfo/rpki). Routinator is
liberally licensed under the [BSD 3-Clause
license](https://github.com/NLnetLabs/routinator/blob/main/LICENSE).

## Launch Smoothly

Getting started with Routinator is really easy by installing a binary package
for either Debian and Ubuntu or for Red Hat Enterprise Linux (RHEL) and
compatible systems such as Rocky Linux. Alternatively, you can run with
Docker or build from the source code using Cargo, Rust’s build system and
package manager.

Please refer to the comprehensive
[documentation](https://routinator.docs.nlnetlabs.nl/) to learn what works
best for you.
