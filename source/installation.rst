.. _doc_routinator_installation:

Installation
============

System Requirements
-------------------

Routinator has minimal system requirements. When choosing a system, make sure
you have 1GB of available memory and 1GB of disk space. This will give you ample
margin for the RPKI repositories to grow over time, as adoption increases. A
powerful CPU is not required.

As new RPKI repositories can emerge in any IP address range and on any domain
name, outbound traffic must not be blocked based on IP or DNS in any way.
Routinator only needs to establish outbound connections via HTTPS and rsync, on
ports 443 and 873, respectively. 


Quick Start
-----------

.. versionadded:: 0.9
   RPM packages

Getting started with Routinator is really easy by either installing a binary
package for Debian and Ubuntu or for Red Hat Enterprise Linux and CentOS. You
can also run with Docker or build from Cargo, Rust's build system and package
manager.

.. tabs::

   .. group-tab:: Deb Packages

       If you have a machine with an amd64/x86_64 architecture running a 
       recent Debian or Ubuntu distribution, you can install Routinator
       from our `software package repository <https://packages.nlnetlabs.nl>`_.
       
       To use this repository, add the line below that corresponds to your
       operating system to your :file:`/etc/apt/sources.list` or
       :file:`/etc/apt/sources.list.d/`:

       .. code-block:: text

          deb [arch=amd64] https://packages.nlnetlabs.nl/linux/debian/ stretch main
          deb [arch=amd64] https://packages.nlnetlabs.nl/linux/debian/ buster main
          deb [arch=amd64] https://packages.nlnetlabs.nl/linux/ubuntu/ xenial main
          deb [arch=amd64] https://packages.nlnetlabs.nl/linux/ubuntu/ bionic main
          deb [arch=amd64] https://packages.nlnetlabs.nl/linux/ubuntu/ focal main

       Then run the following commands to add the public key and update the
       repository list:

       .. code-block:: text

          sudo apt update && apt-get install -y gnupg2
          wget -qO- https://packages.nlnetlabs.nl/aptkey.asc | sudo apt-key add -
          sudo apt update

       You can then install, initialise, enable and start Routinator by running
       these commands. Note that ``routinator-init`` is slightly different than
       the command used with Cargo:

       .. code-block:: bash

          sudo apt install routinator
          sudo routinator-init
          # Follow instructions provided
          sudo systemctl enable --now routinator

       By default, Routinator will start the RTR server on port 3323 and the
       HTTP server on port 8323. These, and other values can be changed in the
       configuration file located in ``/etc/routinator/routinator.conf``. You
       can check the status of Routinator with ``sudo systemctl status
       routinator`` and view the logs with ``sudo journalctl
       --unit=routinator``.

   .. group-tab:: RPM Packages

       If you have a machine with an amd64/x86_64 architecture running a
       :abbr:`RHEL (Red Hat Enterprise Linux)`/CentOS 7 or 8 distribution, you
       can install Routinator from our `software package repository
       <https://packages.nlnetlabs.nl>`_. 
       
       To use this repository, create a file named 
       :file:`/etc/yum.repos.d/nlnetlabs.repo`, enter this configuration and 
       save it:
       
       .. code-block:: text
       
          [nlnetlabs]
          name=NLnet Labs
          baseurl=https://packages.nlnetlabs.nl/linux/centos/$releasever/main/$basearch
          enabled=1
        
       Then run the following command to add the public key:
       
       .. code-block:: bash
       
          sudo rpm --import https://packages.nlnetlabs.nl/aptkey.asc
       
       You can then install, initialise, enable and start Routinator by running
       these commands. Note that ``routinator-init`` is slightly different than
       the command used with Cargo:
        
       .. code-block:: bash
          
          sudo yum install -y routinator
          sudo routinator-init
          # Follow instructions provided
          sudo systemctl enable --now routinator
           
       By default, Routinator will start the RTR server on port 3323 and the
       HTTP server on port 8323. These, and other values can be changed in the
       configuration file located in ``/etc/routinator/routinator.conf``. You
       can check the status of Routinator with ``sudo systemctl status
       routinator`` and view the logs with ``sudo journalctl
       --unit=routinator``.
       
   .. group-tab:: Docker

       Due to the impracticality of complying with the ARIN TAL distribution
       terms in an unsupervised Docker environment, before launching the
       container it is necessary to first review and agree to the `ARIN Relying
       Party Agreement (RPA)
       <https://www.arin.net/resources/manage/rpki/tal/>`_. If you agree to the
       terms, you can let the Routinator Docker image install the TALs into a
       mounted volume that is later reused for the server:

       .. code-block:: bash

          # Create a Docker volume to persist TALs in
          sudo docker volume create routinator-tals
          # Review the ARIN terms.
          # Run a disposable container to install TALs.
          sudo docker run --rm -v routinator-tals:/home/routinator/.rpki-cache/tals \
              nlnetlabs/routinator init -f --accept-arin-rpa
          # Launch the final detached container named 'routinator' exposing RTR on
          # port 3323 and HTTP on port 8323
          sudo docker run -d --restart=unless-stopped --name routinator -p 3323:3323 \
               -p 8323:8323 -v routinator-tals:/home/routinator/.rpki-cache/tals \
               nlnetlabs/routinator
               
   .. group-tab:: Cargo

       Assuming you have a newly installed Debian or Ubuntu machine, you will
       need to install rsync, the C toolchain and Rust. You can then install
       Routinator and start it up as an RTR server listening on 192.0.2.13 port
       3323 and HTTP on port 8323:

       .. code-block:: bash

          apt install curl rsync build-essential
          curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
          source ~/.cargo/env
          cargo install --locked routinator
          routinator init
          # Follow instructions provided
          routinator server --rtr 192.0.2.13:3323 --http 192.0.2.13:8323

       If you have an older version of Rust and Routinator, you can update via:

       .. code-block:: text

          rustup update
          cargo install --locked --force routinator

Installing Specific Versions
----------------------------

Before every new release of Routinator, one or more release candidates are 
provided for testing through every installation method. You can also install
a specific version, if needed.

.. tabs::

   .. group-tab:: Deb Packages

       To install release candidates of Routinator, add the line below that 
       corresponds to your operating system to your ``/etc/apt/sources.list`` or
       ``/etc/apt/sources.list.d/``:

       .. code-block:: text

          deb [arch=amd64] https://packages.nlnetlabs.nl/linux/debian/ stretch-proposed main
          deb [arch=amd64] https://packages.nlnetlabs.nl/linux/debian/ buster-proposed main
          deb [arch=amd64] https://packages.nlnetlabs.nl/linux/ubuntu/ xenial-proposed main
          deb [arch=amd64] https://packages.nlnetlabs.nl/linux/ubuntu/ bionic-proposed main 
          deb [arch=amd64] https://packages.nlnetlabs.nl/linux/ubuntu/ focal-proposed main

       You can use this command to get an overview of the available versions:

       .. code-block:: text

          sudo apt policy routinator

       You can install a specific version using ``<package name>=<version>``,
       e.g.:

       .. code-block:: text

          sudo apt install routinator=0.9.0~rc2-1buster
          
   .. group-tab:: RPM Packages

       To install release candidates of Routinator, create an additional repo 
       file named :file:`/etc/yum.repos.d/nlnetlabs-testing.repo`, enter this
       configuration and save it:
       
       .. code-block:: text
       
          [nlnetlabs-testing]
          name=NLnet Labs Testing
          baseurl=https://packages.nlnetlabs.nl/linux/centos/$releasever/proposed/$basearch
          enabled=1
        
       You can use this command to get an overview of the available versions:
        
       .. code-block:: bash
        
          sudo yum --showduplicates list routinator
          
       You can install a specific version using 
       ``<package name>-<version info>``, e.g.:
         
       .. code-block:: bash
         
          sudo yum install -y routinator-0.9.0~rc2
             
   .. group-tab:: Docker

       All release versions of Routinator, as well as release candidates and
       builds based on the latest main branch are available on `Docker Hub
       <https://hub.docker.com/r/nlnetlabs/routinator/tags?page=1&ordering=last_updated>`_. 
       
       For example, installing Routinator 0.9.0 RC2 is as simple as:
        
       .. code-block:: text
       
          docker run -it nlnetlabs/routinator:v0.9.0-rc2
               
   .. group-tab:: Cargo

       All release versions of Routinator, as well as release candidates, are
       available on `crates.io <https://crates.io/crates/routinator/versions>`_,
       the Rust package registry. If you want to install a specific version of
       Routinator using Cargo, explicitly use the ``--version`` option. If
       needed, use the ``--force`` option to overwrite an existing version:
               
       .. code-block:: text

          cargo install --locked --force routinator --version 0.9.0-rc2

       All new features of Routinator are built on a branch and merged via a
       `pull request <https://github.com/NLnetLabs/routinator/pulls>`_, allowing
       you to easily try them out using Cargo. If you want to try the a specific
       branch from the repository you can use the ``--git`` and ``--branch``
       options:

       .. code-block:: text

          cargo install --git https://github.com/NLnetLabs/routinator.git --branch main
          
       For more installation options refer to the `Cargo book
       <https://doc.rust-lang.org/cargo/commands/cargo-install.html#install-options>`_.

Installing From Source
----------------------

There are three things you need to install and run Routinator: rsync, a C
toolchain and Rust. You can install Routinator on any system where you can
fulfil these requirements.

You need rsync because some RPKI repositories still use it as its main
means of distribution. Some of the cryptographic primitives used by
Routinator require a C toolchain. Lastly, you need Rust because that’s the
programming language that Routinator has been written in.

rsync
"""""

Currently, Routinator requires the :command:`rsync` executable to be in your
path. Due to the nature of rsync, it is unclear which particular version you
need at the very least, but whatever is being shipped with current Linux and
\*BSD distributions, as well as macOS should be fine. Alternatively, you can
download rsync from `the Samba website <https://rsync.samba.org/>`_.

On Windows, Routinator requires the rsync version that comes with
`Cygwin <https://www.cygwin.com/>`_ – make sure to select rsync during the
installation phase.

C Toolchain
"""""""""""

Some of the libraries Routinator depends on require a C toolchain to be present.
Your system probably has some easy way to install the minimum set of packages to
build from C sources. For example, this command will install everything you need
on Debian/Ubuntu:

.. code-block:: text

  apt install build-essential

If you are unsure, try to run :command:`cc` on a command line. If there is a
complaint about missing input files, you are probably good to go.

Rust
""""

The Rust compiler runs on, and compiles to, a great number of platforms, though
not all of them are equally supported. The official `Rust Platform Support
<https://doc.rust-lang.org/nightly/rustc/platform-support.html>`_ page provides
an overview of the various support levels.

While some system distributions include Rust as system packages,
Routinator relies on a relatively new version of Rust, currently 1.47 or
newer. We therefore suggest to use the canonical Rust installation via a
tool called :command:`rustup`.

To install :command:`rustup` and Rust, simply do:

.. code-block:: text

  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

Alternatively, visit the `official Rust website
<https://www.rust-lang.org/tools/install>`_ for other installation methods.

You can update your Rust installation later by running:

.. code-block:: text

  rustup update

Building
""""""""

The easiest way to get Routinator is to leave it to Cargo by saying:

.. code-block:: text

  cargo install --locked routinator

The command will build Routinator and install it in the same directory that
Cargo itself lives in, likely ``$HOME/.cargo/bin``. This means Routinator will
be in your path, too.

Notes
-----

In case you want to build a statically linked Routinator, or you have an
Operating System where special care needs to be taken, such as OpenBSD and
CentOS 6, please refer to the :ref:`doc_routinator_installation_notes`.
