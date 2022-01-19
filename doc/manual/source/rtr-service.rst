RTR Service
===========

Routinator has a built-in server for the RPKI-to-Router (RTR) protocol. It
supports :RFC:`8210` as well as the older version described in :RFC:`6810`. When
launched as an RTR server, routers with support for route origin validation
(ROV) can connect to Routinator to fetch the processed data. 

.. Tip:: If you would like to run the RTR server as a separate daemon, for
         example because you want to centralise validation and distribute
         processed data to various locations where routers can connect, then
         NLnet Labs provides :doc:`RTRTR<rtrtr:index>`.

In order to start the RTR server at 192.0.2.13 and 2001:0DB8::13 on port 3323,
run Routinator using the :subcmd:`server` subcommand:

.. code-block:: text

   routinator server --rtr 192.0.2.13:3323 --rtr [2001:0DB8::13]:3323

Please note that port 3323 is not the :abbr:`IANA (Internet Assigned Numbers
Authority)`-assigned default port for the protocol,  which would be 323. But as
this is a privileged port, you would need to be running Routinator as root when
otherwise there is no reason to do that. 

TLS Connections
---------------

It's possible to use RTR-over-TLS connections with Routinator using the
:option:`--rtr-tls` option. Using the same example as above, the command is:

.. code-block:: text

   routinator server --rtr-tls 192.0.2.13:3323 --rtr-tls [2001:0DB8::13]:3323

There are two additional options you can use. First, the
:option:`--rtr-tls-key` option specifies the path to a file containing the
private key to be used for RTR-over-TLS connections. The file has to contain
exactly one private key encoded in PEM format. Secondly, the
:option:`--rtr-tls-cert` specifies the path to a file containing the server
certificates to be used for RTR-over-TLS connections. The file has to contain
one or more certificates encoded in PEM format.

SSH Connections
---------------

These instructions were contributed by `Wild Kat <https://github.com/wk>`_.

SSH transport for RPKI-RTR can be configured with the help of `netcat
<http://netcat.sourceforge.net/>`_ and `OpenSSH <https://www.openssh.com/>`_.

1. Begin by installing the :program:`openssh-server` and :program:`netcat` packages.

Make sure Routinator is running as an RTR server on localhost:

.. code-block:: text

   routinator server --rtr 127.0.0.1:3323

2. Create a username and a password for the router to log into the host with, such as ``rpki``.

3. Configure OpenSSH to expose an ``rpki-rtr`` subsystem that acts as a proxy into Routinator by editing the :file:`/etc/ssh/sshd_config` file or equivalent to include the following line:

.. code-block:: bash

   # Define an `rpki-rtr` subsystem which is actually `netcat` used to
   # proxy STDIN/STDOUT to a running `routinator server --rtr 127.0.0.1:3323`
   Subsystem       rpki-rtr        /bin/nc 127.0.0.1 3323

   # Certain routers may use old KEX algos and Ciphers which are no longer enabled by default.
   # These examples are required in IOS-XR 5.3 but no longer enabled by default in OpenSSH 7.3
   Ciphers +3des-cbc
   KexAlgorithms +diffie-hellman-group1-sha1
   
   # Only allow the rpki user to execute this one command
   Match User rpki
       ForceCommand /bin/nc localhost 3323
       PasswordAuthentication yes
   Match all

4. Restart the OpenSSH server daemon.

5. Set up the router running IOS-XR using this example configuration:

.. code-block:: text

   router bgp 65534
    rpki server 192.168.0.100
     username rpki
     password <password>
     transport ssh port 22
