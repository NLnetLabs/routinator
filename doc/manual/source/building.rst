Building From Source
====================

In addition to meeting the :ref:`system requirements <installation:System
Requirements>`, there are three things you need to build Routinator: rsync, a
C toolchain and Rust. You can run Routinator on any operating system and CPU
architecture where you can fulfil these requirements.

Dependencies
------------

To get started you need rsync because some RPKI repositories still use it as
its main means of distribution. Some of the cryptographic primitives used by
Routinator require a C toolchain. Lastly, you need Rust because that’s the
programming language that Routinator has been written in.

rsync
"""""

Currently, Routinator requires the :program:`rsync` executable to be in your
path. Due to the nature of rsync, it is unclear which particular version you
need at the very least, but whatever is being shipped with current Linux and
\*BSD distributions, as well as macOS should be fine. Alternatively, you can
download rsync from `the Samba website <https://rsync.samba.org/>`_.

On Windows, Routinator requires the rsync version that comes with
`Cygwin <https://www.cygwin.com/>`_ – make sure to select rsync during the
installation phase.

C Toolchain
"""""""""""

Some of the libraries Routinator depends on require a C toolchain to be
present. Your system probably has some easy way to install the minimum set of
packages to build from C sources. For example, this command will install
everything you need on Debian/Ubuntu:

.. code-block:: text

  apt install build-essential

If you are unsure, try to run :command:`cc` on a command line. If there is a
complaint about missing input files, you are probably good to go.

Rust
""""

The Rust compiler runs on, and compiles to, a great number of platforms,
though not all of them are equally supported. The official `Rust Platform
Support`_ page provides an overview of the various support levels.

While some system distributions include Rust as system packages, Routinator
relies on a relatively new version of Rust, currently |rustversion| or newer.
We therefore suggest to use the canonical Rust installation via a tool called
:program:`rustup`.

Assuming you already have :program:`curl` installed, you can install
:program:`rustup` and Rust by simply entering:

.. code-block:: text

  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

Alternatively, visit the `Rust website
<https://www.rust-lang.org/tools/install>`_ for other installation methods.

Building and Updating
---------------------

In Rust, a library or executable program such as Routinator is called a
*crate*. Crates are published on `crates.io
<https://crates.io/crates/routinator>`_, the Rust package registry. Cargo is
the Rust package manager. It is a tool that allows Rust packages to declare
their various dependencies and ensure that you’ll always get a repeatable
build. 

Cargo fetches and builds Routinator’s dependencies into an executable binary
for your platform. By default you install from crates.io, but you can for
example also install from a specific Git URL, as explained below.

Installing the latest Routinator release from crates.io is as simple as
running:

.. code-block:: text

  cargo install --locked routinator

The command will build Routinator and install it in the same directory that
Cargo itself lives in, likely ``$HOME/.cargo/bin``. This means Routinator
will be in your path, too.

Updating
""""""""

If you want to update to the latest version of Routinator, it’s recommended
to update Rust itself as well, using:

.. code-block:: text

    rustup update

Use the ``--force`` option to overwrite an existing version with the latest
Routinator release:

.. code-block:: text

    cargo install --locked --force routinator

Installing Specific Versions
""""""""""""""""""""""""""""

If you want to install a specific version of
Routinator using Cargo, explicitly use the ``--version`` option. If needed,
use the ``--force`` option to overwrite an existing version:
        
.. code-block:: text

    cargo install --locked --force routinator --version 0.9.0-rc2

All new features of Routinator are built on a branch and merged via a `pull
request <https://github.com/NLnetLabs/routinator/pulls>`_, allowing you to
easily try them out using Cargo. If you want to try a specific branch from
the repository you can use the ``--git`` and ``--branch`` options:

.. code-block:: text

    cargo install --git https://github.com/NLnetLabs/routinator.git --branch main
    
.. Seealso:: For more installation options refer to the `Cargo book
             <https://doc.rust-lang.org/cargo/commands/cargo-install.html#install-options>`_.

Enabling or Disabling Features
""""""""""""""""""""""""""""""

When you build Routinator, `"features"
<https://doc.rust-lang.org/cargo/reference/features.html>`_ provide a
mechanism to express conditional compilation and optional dependencies. The
Routinator package defines a set of named features in the ``[features]``
table of `Cargo.toml
<https://github.com/NLnetLabs/routinator/blob/main/Cargo.toml>`_. The table
also defines if a feature is enabled or disabled by default.

Routinator currently has the following features:

``socks`` —  *Enabled* by default
    Allow the configuration of a SOCKS proxy.
``ui``  —  *Enabled* by default
    Download and build the the `routinator-ui
    <https://crates.io/crates/routinator-ui>`_ crate to run the :doc:`user
    interface<user-interface>`.
``native-tls`` —  *Disabled* by default
    Use the native TLS implementation of your system instead of `rustls
    <https://github.com/rustls/rustls>`_.
``rta`` —  *Disabled* by default
    Let Routinator validate :ref:`advanced-features:Resource Tagged
    Attestations`.

To disable the features that are enabled by default, use the
``--no-default-features`` option. You can then choose which features you want
using the ``--features`` option, listing each feature separated by commas. 

For example, if you want to build Routinator without the user interface, make
sure SOCKS support is retained and use the native TLS implementation, enter
the following command:

.. code-block:: text

   cargo install --locked --no-default-features --features socks,native-tls routinator

If you want to enable a specific feature in the container, this is done via
Docker build args, e.g.

.. code-block:: text

   docker build . --build-arg CARGO_ARGS="--features native-tls"

Building the UI
---------------

Routinator by default ships with an UI that can be accessed on http://localhost:8232/ui/. The UI is independent from Routinator, and lives in a separate repository, namely `routinator-ui <https://github.com/NLnetLabs/routinator-ui/>`_. 

In this example, we will show how to set up the Routinator UI at https://example.org/routinator with a Routinator instance at https://routinator.example.net/ using nginx. This will work equally well with an Apache web server or most other web servers.

First download the routinator-ui repository and build it. The ``--base`` option specifies the path relative to the domain the UI lives, in our case ``/routinator``. The ``ROUTINATOR_API_HOST`` environment variable sets the path where the Routinator API lives.

.. code-block:: bash

    git clone https://github.com/NLnetLabs/routinator-ui
    cd ./routinator-ui
    yarn install
    ROUTINATOR_API_HOST=https://routinator.example.net yarn build --base /routinator

The output files will appear in a folder ``public``. Copy these files to your nginx folder for the UI, e.g. ``/var/www/html/routinator``. This works out of the box with the default configuration using ``try_files``, though you likely want to harden your setup which we will not cover here.

.. code-block:: bash

    apt-get -y install nginx
    mkdir /var/www/html/routinator
    cp -r public/* /var/www/html/routinator/

For the Routinator instance, you might wish to run it behind a reverse proxy as well. See :ref:`our documentation on using a reverse proxy <http-service:Using a Reverse Proxy>` how to do that.


Statically Linked Routinator
----------------------------

While Rust binaries are mostly statically linked, they depend on
:program:`libc` which, as least as :program:`glibc` that is standard on Linux
systems, is somewhat difficult to link statically. This is why Routinator
binaries are actually dynamically linked on :program:`glibc` systems and can
only be transferred between systems with the same :program:`glibc` versions.

However, Rust can build binaries based on the alternative implementation
named :program:`musl` that can easily be statically linked. Building such
binaries is easy with :program:`rustup`. You need to install :program:`musl`
and the correct :program:`musl` target such as ``x86_64-unknown-linux-musl``
for x86\_64 Linux systems. Then you can just build Routinator for that
target.

On a Debian (and presumably Ubuntu) system, enter the following:

.. code-block:: bash

   sudo apt-get install musl-tools
   rustup target add x86_64-unknown-linux-musl
   cargo build --target=x86_64-unknown-linux-musl --release

Platform Specific Instructions
------------------------------

For some platforms, :program:`rustup` cannot provide binary releases to
install directly. The `Rust Platform Support`_ page lists
several platforms where official binary releases are not available, but Rust
is still guaranteed to build. For these platforms, automated tests are not
run so it’s not guaranteed to produce a working build, but they often work to
quite a good degree.

.. _Rust Platform Support:  https://doc.rust-lang.org/nightly/rustc/platform-support.html

OpenBSD
"""""""

On OpenBSD, `patches
<https://github.com/openbsd/ports/tree/master/lang/rust/patches>`_ are
required to get Rust running correctly, but these are well maintained and
offer the latest version of Rust quite quickly.

Rust can be installed on OpenBSD by running:

.. code-block:: bash

   pkg_add rust
