RTR Service
===========

Routinator has a built-in server for the RPKI-to-Router (RTR) protocol. It
supports :RFC:`8210` as well as the older version described in :RFC:`6810`.
When launched as an RTR server, routers with support for route origin
validation (ROV) can connect to Routinator to fetch the processed data. 

.. Tip:: If you would like to run the RTR server as a separate daemon, for
         example because you want to centralise validation and distribute
         processed data to various locations where routers can connect, then
         NLnet Labs provides :doc:`RTRTR<rtrtr:index>`.

In order to start the RTR server at 192.0.2.13 and 2001:0DB8::13 on port
3323, run Routinator using the :subcmd:`server` subcommand:

.. code-block:: text

   routinator server --rtr 192.0.2.13:3323 --rtr [2001:0DB8::13]:3323

Please note that port 3323 is not the :abbr:`IANA (Internet Assigned Numbers
Authority)`-assigned default port for the protocol, which would be 323. But
as this is a privileged port, you would need to be running Routinator as root
when otherwise there is no reason to do that. 

Secure Transports
-----------------

.. versionadded:: 0.11.0
   RTR-over-TLS connections 

Although there is no mandatory-to-implement transport that provides
authentication and integrity protection, :rfc:`6810#section-7` defines a
number of secure transports for RPKI-RTR that can be used to secure
communications. This includes TLS, SSH, TCP MD5 and TCP-AO transports. 

Routinator currently has native support for TLS connections, and can be
configured to use `SSH Transport`_ with some additional tooling.

TLS Transport
"""""""""""""

It's possible to natively use RTR-over-TLS connections with Routinator. The
requirements are described in detail in :rfc:`6810#section-7.2`. There is an
:abbr:`IANA (Internet Assigned Numbers Authority)`-assigned default port for
rpki-rtr-tls as well, in this case 324.

Currently, very few routers have implemented support for TLS, but it may be
especially useful to use secure connections when deploying our RTR data proxy
:doc:`RTRTR <rtrtr:index>`, as data may be flowing across the public
Internet.

In this example we'll start Routinator's RTR server listening on the IP
addresses 192.0.2.13 and 2001:0DB8::13 and use port 3324 to make sure it's
not a priviledged port. 

First, indidate that you want a TLS connection with the :option:`--rtr-tls`
option. Then use the :option:`--rtr-tls-cert` option to specify the path to a
file containing the server certificates to be used. This file has to contain
one or more certificates encoded in PEM format. Lastly, use the
:option:`--rtr-tls-key` option to specify the path to a file containing the
private key to be used for RTR-over-TLS connections. The file has to contain
exactly one private key encoded in PEM format:

.. code-block:: text

   routinator server --rtr-tls 192.0.2.13:3324 \
                     --rtr-tls [2001:0DB8::13]:3324 \
                     --rtr-tls-cert "/path/to/rtr-tls.crt" \
                     --rtr-tls-key "/path/to/rtr-tls.key"

If you want to connect to Routinator with RTRTR using an :ref:`RTR-TLS
Unit<rtrtr:configuration:rtr unit>`, a certificate that is trusted by the
usual set of web trust anchors will work with no additional configuration. In
case you generated a self-signed certificate for Routinator, make sure to
copy the certificate to your machine running RTRTR and refer to the path of
the file in your unit using the ``cacerts`` configuration option. 

SSH Transport
"""""""""""""

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
