Installation
============

System Requirements
-------------------

Routinator has minimal system requirements. When choosing a system, make sure
you have 1GB of available memory and 4GB of disk space for the application.
This will give you ample margin for the RPKI repositories to grow over time,
as adoption increases. A powerful CPU is not required.

As new RPKI repositories can emerge in any IP address range and on any domain
name, outbound traffic must not be blocked based on IP or DNS in any way.
Routinator only needs to establish outbound connections via HTTPS and rsync,
on ports 443 and 873, respectively. 

Binary Packages
---------------

Getting started with Routinator is really easy by installing a binary package
for either Debian and Ubuntu or for Red Hat Enterprise Linux (RHEL) and
compatible systems such as Rocky Linux. Alternatively, you can run with
Docker. Packages and Docker images are currently available for the
``amd64``/``x86_64`` architecture only.

You can also build Routinator from the source code using Cargo, Rust's build
system and package manager. Cargo lets you to run Routinator on almost any
operating system and CPU architecture. Refer to the :doc:`building` section
to get started.

.. tabs::

   .. group-tab:: Debian

       The NLnet Labs software package repository has binary packages
       available for Debian 9 (stretch), 10 (buster) and 11 (bullseye).
       
       First update the :program:`apt` package index: 

       .. code-block:: bash

          sudo apt update

       Then install packages to allow :program:`apt` to use a repository over HTTPS:

       .. code-block:: bash

          sudo apt install \
            ca-certificates \
            curl \
            gnupg \
            lsb-release

       Add the GPG key from NLnet Labs:

       .. code-block:: bash

          curl -fsSL https://packages.nlnetlabs.nl/aptkey.asc | sudo gpg --dearmor -o /usr/share/keyrings/nlnetlabs-archive-keyring.gpg

       Now, use the following command to set up the *main* repository:

       .. code-block:: bash

          echo \
          "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/nlnetlabs-archive-keyring.gpg] https://packages.nlnetlabs.nl/linux/debian \
          $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/nlnetlabs.list > /dev/null

       Update the :program:`apt` package index once more: 

       .. code-block:: bash

          sudo apt update

       You can now install Routinator with:

       .. code-block:: bash

          sudo apt install routinator

       Before running Routinator for the first time, you must prepare the
       directory for the local RPKI cache, as well as the directory where the
       :term:`Trust Anchor Locator (TAL)` files reside. After entering this
       command, **follow the instructions** provided about the ARIN TAL:

       .. code-block:: bash

          sudo routinator-init

       To learn more about this process refer to the :doc:`initialisation`
       section. After successful initialisation you can enable Routinator
       with:

       .. code-block:: bash

          sudo systemctl enable --now routinator

       By default, Routinator will start the RTR server on port 3323 and the
       HTTP server on port 8323. These, and other values can be changed in
       the :doc:`configuration file<configuration>` located in
       :file:`/etc/routinator/routinator.conf`. 
       
       You can check the status of Routinator with:
       
       .. code-block:: bash 
       
          sudo systemctl status routinator
       
       You can view the logs with: 
       
       .. code-block:: bash
       
          sudo journalctl --unit=routinator

   .. group-tab:: Ubuntu

       The NLnet Labs software package repository has binary packages
       available for Ubuntu 16.x (Xenial Xerus), 18.x (Bionic Beaver) and
       20.x (Focal Fossa).
       
       First update the :program:`apt` package index: 

       .. code-block:: bash

          sudo apt update

       Then install packages to allow :program:`apt` to use a repository over HTTPS:

       .. code-block:: bash

          sudo apt install \
            ca-certificates \
            curl \
            gnupg \
            lsb-release

       Add the GPG key from NLnet Labs:

       .. code-block:: bash

          curl -fsSL https://packages.nlnetlabs.nl/aptkey.asc | sudo gpg --dearmor -o /usr/share/keyrings/nlnetlabs-archive-keyring.gpg

       Now, use the following command to set up the *main* repository:

       .. code-block:: bash

          echo \
          "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/nlnetlabs-archive-keyring.gpg] https://packages.nlnetlabs.nl/linux/ubuntu \
          $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/nlnetlabs.list > /dev/null

       Update the :program:`apt` package index once more: 

       .. code-block:: bash

          sudo apt update

       You can now install Routinator with:

       .. code-block:: bash

          sudo apt install routinator

       Before running Routinator for the first time, you must prepare the
       directory for the local RPKI cache, as well as the directory where the
       :term:`Trust Anchor Locator (TAL)` files reside. After entering this
       command, **follow the instructions** provided about the ARIN TAL:

       .. code-block:: bash

          sudo routinator-init

       To learn more about this process refer to the :doc:`initialisation`
       section. After successful initialisation you can enable Routinator
       with:

       .. code-block:: bash

          sudo systemctl enable --now routinator

       By default, Routinator will start the RTR server on port 3323 and the
       HTTP server on port 8323. These, and other values can be changed in
       the :doc:`configuration file<configuration>` located in
       :file:`/etc/routinator/routinator.conf`. 
       
       You can check the status of Routinator with:
       
       .. code-block:: bash 
       
          sudo systemctl status routinator
       
       You can view the logs with: 
       
       .. code-block:: bash
       
          sudo journalctl --unit=routinator

   .. group-tab:: RHEL/CentOS

       The NLnet Labs software package repository has binary packages
       available for RHEL 7 and 8 and compatible operating system such as
       Rocky Linux.
       
       First create a file named :file:`/etc/yum.repos.d/nlnetlabs.repo`,
       enter this configuration and save it:
       
       .. code-block:: text
       
          [nlnetlabs]
          name=NLnet Labs
          baseurl=https://packages.nlnetlabs.nl/linux/centos/$releasever/main/$basearch
          enabled=1
        
       Add the GPG key from NLnet Labs:
       
       .. code-block:: bash
       
          sudo rpm --import https://packages.nlnetlabs.nl/aptkey.asc
       
       You can now install Routinator with:

       .. code-block:: bash

          sudo yum install -y routinator

       Before running Routinator for the first time, you must prepare the
       directory for the local RPKI cache, as well as the directory where the
       :term:`Trust Anchor Locator (TAL)` files reside. After entering this
       command, **follow the instructions** provided about the ARIN TAL:

       .. code-block:: bash

          sudo routinator-init

       To learn more about this process refer to the :doc:`initialisation`
       section. After successful initialisation you can enable Routinator
       with:

       .. code-block:: bash

          sudo systemctl enable --now routinator

       By default, Routinator will start the RTR server on port 3323 and the
       HTTP server on port 8323. These, and other values can be changed in
       the :doc:`configuration file<configuration>` located in
       :file:`/etc/routinator/routinator.conf`. 
       
       You can check the status of Routinator with:
       
       .. code-block:: bash 
       
          sudo systemctl status routinator
       
       You can view the logs with: 
       
       .. code-block:: bash
       
          sudo journalctl --unit=routinator
       
   .. group-tab:: Docker

       Due to the impracticality of complying with terms and conditions in an
       unsupervised Docker environment, before launching the container it is
       necessary to first review and agree to the `ARIN Relying Party
       Agreement (RPA) <https://www.arin.net/resources/manage/rpki/tal/>`_.
       If you agree, you can let the Routinator Docker image install the
       :term:`Trust Anchor Locator (TAL)` files into a mounted volume that is
       later reused for the server.

       First, create a Docker volume to persist the TAL files in:

       .. code-block:: bash

          sudo docker volume create routinator-tals

       Then run a disposable container to install the TALs:

       .. code-block:: bash

          sudo docker run --rm -v routinator-tals:/home/routinator/.rpki-cache/tals \
              nlnetlabs/routinator init -f --accept-arin-rpa

       Finally, launch the detached container named *routinator*, exposing
       the :term:`RPKI-to-Router (RPKI-RTR)` protocol on port 3323 and HTTP
       on port 8323:

       .. code-block:: bash

          sudo docker run -d --restart=unless-stopped --name routinator -p 3323:3323 \
               -p 8323:8323 -v routinator-tals:/home/routinator/.rpki-cache/tals \
               nlnetlabs/routinator
               
       The Routinator container is known to run successfully run under 
       `gVisor <https://gvisor.dev/>`_ for additional isolation.

.. versionadded:: 0.9
   RPM packages

Updating
--------

.. tabs::

   .. group-tab:: Debian

       To update an existing Routinator installation, first update the 
       repository using:

       .. code-block:: text

          sudo apt update

       You can use this command to get an overview of the available versions:

       .. code-block:: text

          sudo apt policy routinator

       You can upgrade an existing Routinator installation to the latest
       version using:

       .. code-block:: text

          sudo apt --only-upgrade install routinator

   .. group-tab:: Ubuntu

       To update an existing Routinator installation, first update the 
       repository using:

       .. code-block:: text

          sudo apt update

       You can use this command to get an overview of the available versions:

       .. code-block:: text

          sudo apt policy routinator

       You can upgrade an existing Routinator installation to the latest
       version using:

       .. code-block:: text

          sudo apt --only-upgrade install routinator

   .. group-tab:: RHEL/CentOS

       To update an existing Routinator installation, you can use this
       command to get an overview of the available versions:
        
       .. code-block:: bash
        
          sudo yum --showduplicates list routinator
          
       You can update to the latest version using:
         
       .. code-block:: bash
         
          sudo yum update -y routinator
             
   .. group-tab:: Docker

       Upgrading to the latest version of Routinator can be done with:
        
       .. code-block:: text
       
          docker run -it nlnetlabs/routinator:latest

Installing Specific Versions
----------------------------

Before every new release of Routinator, one or more release candidates are 
provided for testing through every installation method. You can also install
a specific version, if needed.

.. tabs::

   .. group-tab:: Debian

       If you would like to try out release candidates of Routinator you can
       add the *proposed* repository to the existing *main* repository
       described earlier. 
       
       Assuming you already have followed the steps to install regular releases,
       run this command to add the additional repository:

       .. code-block:: bash

          echo \
          "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/nlnetlabs-archive-keyring.gpg] https://packages.nlnetlabs.nl/linux/debian \
          $(lsb_release -cs)-proposed main" | sudo tee /etc/apt/sources.list.d/nlnetlabs-proposed.list > /dev/null

       Make sure to update the :program:`apt` package index:

       .. code-block:: bash

          sudo apt update
       
       You can now use this command to get an overview of the available 
       versions:

       .. code-block:: bash

          sudo apt policy routinator

       You can install a specific version using ``<package name>=<version>``,
       e.g.:

       .. code-block:: bash

          sudo apt install routinator=0.9.0~rc2-1buster

   .. group-tab:: Ubuntu

       If you would like to try out release candidates of Routinator you can
       add the *proposed* repository to the existing *main* repository
       described earlier. 
       
       Assuming you already have followed the steps to install regular
       releases, run this command to add the additional repository:

       .. code-block:: bash

          echo \
          "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/nlnetlabs-archive-keyring.gpg] https://packages.nlnetlabs.nl/linux/ubuntu \
          $(lsb_release -cs)-proposed main" | sudo tee /etc/apt/sources.list.d/nlnetlabs-proposed.list > /dev/null

       Make sure to update the :program:`apt` package index:

       .. code-block:: bash

          sudo apt update
       
       You can now use this command to get an overview of the available 
       versions:

       .. code-block:: bash

          sudo apt policy routinator

       You can install a specific version using ``<package name>=<version>``,
       e.g.:

       .. code-block:: bash

          sudo apt install routinator=0.9.0~rc2-1bionic
          
   .. group-tab:: RHEL/CentOS

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
               