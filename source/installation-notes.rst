.. _doc_routinator_installation_notes:

Installation Notes
==================

In certain scenarios and on some platforms specific steps are needed in order to
get Routinator working as desired.

Statically Linked Routinator
----------------------------

While Rust binaries are mostly statically linked, they depend on :command:`libc`
which, as least as :command:`glibc` that is standard on Linux systems, is
somewhat difficult to link statically. This is why Routinator binaries are
actually dynamically linked on :command:`glibc` systems and can only be
transferred between systems with the same :command:`glibc` versions.

However, Rust can build binaries based on the alternative implementation named
:command:`musl` that can easily be statically linked. Building such binaries is
easy with :command:`rustup`. You need to install :command:`musl` and the correct
:command:`musl` target such as ``x86_64-unknown-linux-musl`` for x86\_64 Linux
systems. Then you can just build Routinator for that target.

On a Debian (and presumably Ubuntu) system, enter the following:

.. code-block:: bash

   sudo apt-get install musl-tools
   rustup target add x86_64-unknown-linux-musl
   cargo build --target=x86_64-unknown-linux-musl --release

Platform Specific Instructions
------------------------------

.. Tip:: GÉANT has created an
         `Ansible playbook <https://github.com/GEANT/rpki-validation-tools>`_
         defining a role to deploy Routinator on Ubuntu.

For some platforms, :command:`rustup` cannot provide binary releases to install
directly. The `Rust Platform Support
<https://forge.rust-lang.org/platform-support.html>`_ page lists several
platforms where official binary releases are not available, but Rust is still
guaranteed to build. For these platforms, automated tests are not run so it’s
not guaranteed to produce a working build, but they often work to quite a good
degree.

OpenBSD
"""""""

On OpenBSD, `patches
<https://github.com/openbsd/ports/tree/master/lang/rust/patches>`_ are required
to get Rust running correctly, but these are well maintained and offer the
latest version of Rust quite quickly.

Rust can be installed on OpenBSD by running:

.. code-block:: bash

   pkg_add rust

CentOS 6
""""""""

The standard installation method does not work when using CentOS 6. Here, you
will end up with a long list of error messages about missing assembler
instructions. This is because the assembler shipped with CentOS 6 is too old.

You can get the necessary version by installing the `Developer Toolset 6
<https://www.softwarecollections.org/en/scls/rhscl/devtoolset-6/>`_ from the
`Software Collections
<https://wiki.centos.org/AdditionalResources/Repositories/SCL>`_ repository. On
a virgin system, you can install Rust using these steps:

.. code-block:: bash

   sudo yum install centos-release-scl
   sudo yum install devtoolset-6
   scl enable devtoolset-6 bash
   curl https://sh.rustup.rs -sSf | sh
   source $HOME/.cargo/env

SELinux using CentOS 7
""""""""""""""""""""""

This guide, contributed by `Rich Compton
<https://github.com/racompton/routinator_centos7_install>`_, describes how to
run Routinator on Security Enhanced Linux (SELinux) using CentOS 7.

1. Start by setting the hostname.

.. code-block:: bash

  sudo nmtui-hostname
  Hostname will be set

2.	Set the interface and connect it.

.. Note:: Ensure that "Automatically connect" and "Available to all users"
          are checked.

.. code-block:: bash

  sudo nmtui-edit

3.	Install the required packages.

.. code-block:: bash

  sudo yum check-update
  sudo yum upgrade -y
  sudo yum install -y epel-release
  sudo yum install -y vim wget curl net-tools lsof bash-completion yum-utils \
      htop nginx httpd-tools tcpdump rust cargo rsync policycoreutils-python

4.	Set the timezone to UTC.

.. code-block:: bash

  sudo timedatectl set-timezone UTC

5.	Remove postfix as it is unneeded.

.. code-block:: bash

  sudo systemctl stop postfix
  sudo systemctl disable postfix

6.	Create a self-signed certificate for NGINX.

.. code-block:: bash

  sudo mkdir /etc/ssl/private
  sudo chmod 700 /etc/ssl/private
  sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
      -keyout /etc/ssl/private/nginx-selfsigned.key \
      -out /etc/ssl/certs/nginx-selfsigned.crt
  # Populate the relevant information to generate a self signed certificate
  sudo openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048

7.	Add in the :file:`ssl.conf` file to :file:`/etc/nginx/conf.d/ssl.conf` and edit the :file:`ssl.conf` file to provide the IP of the host in the ``server_name`` field.

8.	Replace :file:`/etc/nginx/nginx.conf` with the :file:`nginx.conf` file.

9.	Set the username and password for the web interface authentication.

.. code-block:: bash

  sudo htpasswd -c /etc/nginx/.htpasswd <username>

10.	Start Nginx and set it up so it starts at boot.

.. code-block:: bash

  sudo systemctl start nginx
  sudo systemctl enable nginx


11.	Add the user "routinator", create the ``/opt/routinator`` directory and assign it to the "routinator" user and group

.. code-block:: bash

  sudo useradd routinator
  sudo mkdir /opt/routinator
  sudo chown routinator:routinator /opt/routinator

12.	Sudo into the routinator user.

.. code-block:: bash

  sudo su - routinator

13.	Install Routinator and add it to the ``$PATH`` for user "routinator"

.. code-block:: bash

  cargo install routinator
  vi /home/routinator/.bash_profile
  Edit the PATH line to include "/home/routinator/.cargo/bin"
  PATH=$PATH:$HOME/.local/bin:$HOME/bin:/home/routinator/.cargo/bin

14.	Initialise Routinator, accept the ARIN TAL and exit back to the user with ``sudo``.

.. code-block:: bash

  /home/routinator/.cargo/bin/routinator -b /opt/routinator init -f --accept-arin-rpa
  exit

15.	Create a routinator systemd script using the template below.

.. code-block:: bash

  sudo vi /etc/systemd/system/routinator.service
  [Unit]
  Description=Routinator RPKI Validator and RTR Server
  After=network.target
  [Service]
  Type=simple
  User=routinator
  Group=routinator
  Restart=on-failure
  RestartSec=90
  ExecStart=/home/routinator/.cargo/bin/routinator -v -b /opt/routinator server \
      --http 127.0.0.1:8080 --rtr <IPv4 IP>:8323 --rtr [<IPv6 IP>]:8323
  TimeoutStartSec=0
  [Install]
  WantedBy=default.target

.. Note:: You must populate the IPv4 and IPv6 addresses. In addition, the IPv6
          address needs to have brackets '[ ]' around it. For example:

          .. code-block:: bash

            /home/routinator/.cargo/bin/routinator -v -b /opt/routinator server \
            --http 127.0.0.1:8080 --rtr 172.16.47.235:8323 --rtr [2001:db8::43]:8323

16.	Configure SELinux to allow connections to localhost and to allow rsync to write to the ``/opt/routinator`` directory.

.. code-block:: bash

  sudo setsebool -P httpd_can_network_connect 1
  sudo semanage permissive -a rsync_t

17.	Reload the systemd daemon and set the routinator service to start at boot.

.. code-block:: bash

  sudo systemctl daemon-reload
  sudo systemctl enable routinator.service
  sudo systemctl start routinator.service

18.	Set up the firewall to permit ssh, HTTPS and port 8323 for the RTR protocol.

.. code-block:: bash

  sudo firewall-cmd --permanent --remove-service=ssh --zone=public
  sudo firewall-cmd --permanent --zone public --add-rich-rule='rule family="ipv4" \
      source address="<IPv4 management subnet>" service name=ssh accept'
  sudo firewall-cmd --permanent --zone public --add-rich-rule='rule family="ipv6" \
      source address="<IPv6 management subnet>" service name=ssh accept'
  sudo firewall-cmd --permanent --zone public --add-rich-rule='rule family="ipv4" \
      source address="<IPv4 management subnet>" service name=https accept'
  sudo firewall-cmd --permanent --zone public --add-rich-rule='rule family="ipv6" \
      source address="<IPv6 management subnet>" service name=https accept'
  sudo firewall-cmd --permanent --zone public --add-rich-rule='rule family="ipv4" \
      source address="<peering router IPv4 loopback subnet>" port port=8323 protocol=tcp accept'
  sudo firewall-cmd --permanent --zone public --add-rich-rule='rule family="ipv6" \
      source address="<peering router IPv6 loopback subnet>" port port=8323 protocol=tcp accept'
  sudo firewall-cmd --reload

19. Navigate to ``https://<IP address of rpki-validator>/metrics`` to see if it's working. You should authenticate with the username and password that you provided in step 10 of setting up the RPKI Validation Server.
