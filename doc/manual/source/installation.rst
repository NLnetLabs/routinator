Installation
============

System Requirements
-------------------

Routinator has minimal system requirements. When choosing a system, a
powerful CPU is not required. Make sure you have 1GB of available memory and
4GB of disk space for the application. 

Please keep in mind that the RPKI consists of a great number of small files.
As a result, Routinator will use a large amount of inodes. You should
accommodate for at least 500,000 inodes, but one million will provide more
breathing room. This will give you ample margin for the RPKI repositories to
grow over time, as adoption increases. 

.. Tip:: The ``df -i`` command shows the amount of inodes available, used,
         and free.

As new RPKI repositories can emerge in any IP address range and on any domain
name, outbound traffic must not be blocked based on IP or DNS in any way.
Routinator only needs to establish outbound connections via HTTPS and rsync,
on ports 443 and 873, respectively. 

Binary Packages
---------------

Getting started with Routinator is really easy by installing a binary package
for either Debian and Ubuntu or for Red Hat Enterprise Linux (RHEL) and
compatible systems such as Rocky Linux. Alternatively, you can run with
Docker. 

You can also build Routinator from the source code using Cargo, Rust's build
system and package manager. Cargo lets you to run Routinator on almost any
operating system and CPU architecture. Refer to the :doc:`building` section
to get started.

.. tabs::

   .. group-tab:: Debian

       To install a Routinator package, you need the 64-bit version of one of
       these Debian versions:

         -  Debian Bullseye 11
         -  Debian Buster 10
         -  Debian Stretch 9

       Packages for the ``amd64``/``x86_64`` architecture are available for
       all listed versions. In addition, we offer ``armhf`` architecture
       packages for Debian/Raspbian Bullseye, and ``arm64`` for Buster.
       
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

       After installation Routinator will run immediately as the user
       *routinator* and be configured to start at boot. By default, it will
       run the RTR server on port 3323 and the HTTP server on port 8323.
       These, and other values can be changed in the :doc:`configuration
       file<configuration>` located in
       :file:`/etc/routinator/routinator.conf`. 
       
       You can check the status of Routinator with:
       
       .. code-block:: bash 
       
          sudo systemctl status routinator
       
       You can view the logs with: 
       
       .. code-block:: bash
       
          sudo journalctl --unit=routinator

   .. group-tab:: Ubuntu

       To install a Routinator package, you need the 64-bit version of one of
       these Ubuntu versions:

         - Ubuntu Jammy 22.04 (LTS)
         - Ubuntu Focal 20.04 (LTS)
         - Ubuntu Bionic 18.04 (LTS)
         - Ubuntu Xenial 16.04 (LTS)

       Packages are available for the ``amd64``/``x86_64`` architecture only.
       
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

       After installation Routinator will run immediately as the user
       *routinator* and be configured to start at boot. By default, it will
       run the RTR server on port 3323 and the HTTP server on port 8323.
       These, and other values can be changed in the :doc:`configuration
       file<configuration>` located in
       :file:`/etc/routinator/routinator.conf`. 
       
       You can check the status of Routinator with:
       
       .. code-block:: bash 
       
          sudo systemctl status routinator
       
       You can view the logs with: 
       
       .. code-block:: bash
       
          sudo journalctl --unit=routinator

   .. group-tab:: RHEL/CentOS

       To install a Routinator package, you need Red Hat Enterprise Linux
       (RHEL) 7 or 8, or compatible operating system such as Rocky Linux.
       Packages are available for the ``amd64``/``x86_64`` architecture only.
       
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

       After installation Routinator will run immediately as the user
       *routinator* and be configured to start at boot. By default, it will
       run the RTR server on port 3323 and the HTTP server on port 8323.
       These, and other values can be changed in the :doc:`configuration
       file<configuration>` located in
       :file:`/etc/routinator/routinator.conf`. 
       
       You can check the status of Routinator with:
       
       .. code-block:: bash 
       
          sudo systemctl status routinator
       
       You can view the logs with: 
       
       .. code-block:: bash
       
          sudo journalctl --unit=routinator
       
   .. group-tab:: Docker

       Routinator Docker images are built with Alpine Linux. The supported CPU
       architectures are shown on the `Docker Hub Routinator page <https://hub.docker.com/r/nlnetlabs/routinator/tags>`_
       per Routinator version (aka Docker "tag") in the `OS/ARCH` column.

       To run Routinator as a background daemon with the default settings (RTR
       server on port 3323 and HTTP server on port 8323) can be done like so:

       .. code-block:: bash

          sudo docker run -d --restart=unless-stopped --name routinator \
              -p 3323:3323 \
              -p 8323:8323 \
              nlnetlabs/routinator
               
       The Routinator container is known to run successfully run under 
       `gVisor <https://gvisor.dev/>`_ for additional isolation.

       To adjust the configuration you can pass command line arguments to
       Routinator (try ``--help`` for more information) and/or supply your
       own Routinator configuration file (by mapping it from the host info
       the container using ``-v host/path/to/routinator.conf:/etc/routinator.conf``
       and passing ``--config /etc/routinator.conf`` when running the container).

       To persist the RPKI cache data you can create a separate Docker volume
       and mount it into the container like so:

       .. code-block:: bash

          sudo docker volume create rpki-cache
          sudo docker run <your usual arguments> \
              -v rpki-cache:/home/routinator/.rpki-cache \
              nlnetlabs/routinator

.. versionadded:: 0.9.0
   RPM packages
.. versionadded:: 0.11.0
   Debian packages for ``armhf`` and ``arm64`` architecture
.. versionadded:: 0.11.2
   Ubuntu packages for Jammy 22.04 (LTS)
.. deprecated:: 0.12.0
   ``routinator-init`` and ``--accept-arin-rpa``

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

       Assuming that you run Docker with image `nlnetlabs/routinator`, upgrading
       to the latest version can be done by running the following commands:
        
       .. code-block:: text
       
          sudo docker pull nlnetlabs/routinator
          sudo docker stop routinator
          sudo docker run <your usual arguments> nlnetlabs/routinator

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
       
          sudo docker run <your usual arguments> nlnetlabs/routinator:v0.9.0-rc2
               
