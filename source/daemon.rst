.. _doc_routinator_daemon:

Running as a Daemon
===================

Routinator can run as a service that periodically fetches RPKI data, verifies it
and makes the resulting data set available through the built-in HTTP server and
via the RTR protocol. You can start the Routinator service using the
:subcmd:`server` subcommand.

The HTTP Service
----------------

In addition to the various VRP output formats, Routinator's HTTP server also
provides an API, a :ref:`user interface <doc_routinator_ui>` and
:ref:`monitoring endpoints <doc_routinator_monitoring>`. The server is not
enabled by default for security reasons, nor does it have a default host or
port.

Please note that the HTTP server is intended to run on your internal network and
doesn't offer HTTPS natively. If this is a requirement, you can for example run
Routinator behind an `NGINX <https://www.nginx.com>`_ reverse proxy.

In order to start the HTTP server at 192.0.2.13 and 2001:0DB8::13 on port 8323,
run:

.. code-block:: bash

   routinator server --http 192.0.2.13:8323 --http [2001:0DB8::13]:8323

The application will stay attached to your terminal unless you provide the
:option:`--detach` option. 

Output Formats
""""""""""""""

After fetching and verifying all RPKI data, the following paths are available:

:command:`/csv`
     Returns the current set of VRPs in **csv** output format

:command:`/csvext`
     Returns the current set of VRPs in **csvext** output format.

:command:`/json`
     Returns the current set of VRPs in **json** output format

:command:`/openbgpd`
     Returns the current set of VRPs in **OpenBGPD** output format

:command:`/bird`
     Returns the current set of VRPs in **bird** output format

:command:`/bird2`
     Returns the current set of VRPs in **bird2** output format

:command:`/rpsl`
     Returns the current set of VRPs in **RPSL** output format

API Endpoints
"""""""""""""

The service supports GET requests with the following paths:

:command:`/metrics`
     Returns a set of :ref:`monitoring <doc_routinator_monitoring>` metrics in 
     the format used by Prometheus.

:command:`/status`
     Returns the current status of the Routinator instance. This is similar to 
     the output of the :command:`/metrics` endpoint but in a more human friendly
     format.

:command:`/log`
     Returns the logging output of the last validation run. The log level 
     matches that set upon start.

     Note that the output is collected after each validation run and is 
     therefore only available after the initial run has concluded.

:command:`/version`
     Returns the version of the Routinator instance.

:command:`/api/v1/validity/as-number/prefix`
     Returns a JSON object describing whether the route announcement given by 
     its origin AS number and address prefix is RPKI valid, invalid, or not 
     found. A complete list of VRPs that caused the result is included.
     
:command:`/validity?asn=as-number&prefix=prefix`
     Same as above but with a more form-friendly calling convention.

These paths accept filter expressions to limit the VRPs returned in the form of
a query string. The field ``filter-asn`` can be used to filter for ASNs and the
field ``filter-prefix`` can be used to filter for prefixes. The fields can be
repeated multiple times.

The RTR Service
---------------

Routinator supports RPKI-RTR as specified in :RFC:`8210` as well as
the older version described in :RFC:`6810`.

When launched as an RTR server, routers with support for route origin validation
(ROV) can connect to Routinator to fetch the processed data. This includes
hardware  routers such as `Juniper
<https://www.juniper.net/documentation/en_US/junos/topics/topic-map/bgp-origin
-as-validation.html>`_, `Cisco
<https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/iproute_bgp/configuration/
15-s/irg-15-s-book/irg-origin-as.html>`_ and `Nokia
<https://infocenter.alcatel-lucent.com/public/7750SR160R4A/index.jsp?topic=%
2Fcom.sr.unicast%2Fhtml%2Fbgp.html&cp=22_4_7_2&anchor=d2e5366>`_, as well as
software solutions like `BIRD <https://bird.network.cz/>`_, `GoBGP
<https://osrg.github.io/gobgp/>`_ and :ref:`others <doc_rpki_rtr>`.

Like the HTTP server, the RTR server is not started by default, nor does it have
a default host or port. Thus, in order to start the RTR server at 192.0.2.13 and
2001:0DB8::13 on port 3323, run Routinator using the :subcmd:`server` command:

.. code-block:: bash

   routinator server --rtr 192.0.2.13:3323 --rtr [2001:0DB8::13]:3323

Please note that port 3323 is not the IANA-assigned default port for the
protocol,  which would be 323. But as this is a privileged port, you would need
to be running Routinator as root when otherwise there is no reason to do that.
The application will stay attached to your terminal unless you provide the
:option:`--detach` option.

By default, the repository will be updated and verified every 10 minutes.
You can change this via the :option:`--refresh` option and specify the interval
between verification in seconds. That is, if you rather have Routinator
validate every 15 minutes, the above command becomes:

.. code-block:: bash

   routinator server --rtr 192.0.2.13:3323 --rtr [2001:0DB8::13]:3323 --refresh=900

Communication between Routinator and the router using the RPKI-RTR protocol is
done via plain TCP. Below, there is an explanation how to secure the transport
using either SSH or TLS.

.. _doc_routinator_rtr_secure_transport:

Secure Transports
"""""""""""""""""

These instructions were contributed by `wk on Github <https://github.com/NLnetLabs/routinator/blob/master/doc/transports.md>`_.

:rfc:`6810#section-7` defines a number of secure transports for RPKI-RTR that
can be used to secure communication between a router and a RPKI relying party.

However, the RPKI Router Implementation Report documented in
:rfc:`7128#section-5` suggests these secure transports have not been widely
implemented. Implementations, however, do exist, and a secure transport could be
valuable in situations where the RPKI relying party is provided as a public
service, or across a non-trusted network.

SSH Transport
+++++++++++++

SSH transport for RPKI-RTR can be configured with the help of `netcat
<http://netcat.sourceforge.net/>`_ and `OpenSSH <https://www.openssh.com/>`_.

1. Begin by installing the :command:`openssh-server` and :command:`netcat` packages.

Make sure Routinator is running as an RTR server on localhost:

.. code-block:: bash

   routinator server --rtr 127.0.0.1:3323

2. Create a username and a password for the router to log into the host with, such as ``rpki``.

3. Configure OpenSSH to expose an ``rpki-rtr`` subsystem that acts as a proxy into Routinator by editing the :file:`/etc/ssh/sshd_config` file or equivalent to include the following line:

.. code-block:: text

   # Define an `rpki-rtr` subsystem which is actually `netcat` used to
   # proxy STDIN/STDOUT to a running `routinator server --rtr 127.0.0.1:3323`
   Subsystem       rpki-rtr        /bin/nc 127.0.0.1 3323

   # Certain routers may use old KEX algos and Ciphers which are no longer enabled by default.
   # These examples are required in IOS-XR 5.3 but no longer enabled by default in OpenSSH 7.3
   Ciphers +3des-cbc
   KexAlgorithms +diffie-hellman-group1-sha1

4. Restart the OpenSSH server daemon.

5. Set up the router running IOS-XR using this example configuration:

.. code-block:: bash

   router bgp 65534
    rpki server 192.168.0.100
     username rpki
     password rpki
     transport ssh port 22


TLS Transport
+++++++++++++

TLS transport for RPKI-RTR can be configured with the help of `stunnel
<https://www.stunnel.org/>`_.

1. Begin by installing the :command:`stunnel` package.

2. Make sure Routinator is running as an RTR server on localhost:

.. code-block:: bash

   routinator server --rtr 127.0.0.1:3323

3. Acquire (via for example `Let's Encrypt <https://letsencrypt.org/>`_) or generate an SSL certificate. In the example below, an SSL certificate for the domain example.com generated by Let's Encrypt is used.

4. Create an stunnel configuration file by editing :file:`/etc/stunnel/rpki.conf` or equivalent:

.. code-block:: text

   [rpki]
   ; Use a letsencrypt certificate for example.com
   cert = /etc/letsencrypt/live/example.com/fullchain.pem
   key = /etc/letsencrypt/live/example.com/privkey.pem

   ; Listen for TLS rpki-rtr on port 323 and proxy to port 3323 on localhost
   accept = 323
   connect = 127.0.0.1:3323

5. Restart :command:`stunnel` to complete the process.
