.. _doc_routinator_daemon:

Running as a Daemon
===================

Routinator can run as a service that periodically fetches RPKI data, verifies it
and makes the resulting data set available through the built-in HTTP server and
via the RTR protocol. You can start the Routinator service using the
:subcmd:`server` subcommand.

.. Note:: Routinator will not reread the trust anchor locators after it has
          started the service. Thus, if you add or change a TAL you must restart
          Routinator or send it a :ref:`SIGUSR1 <manpage_signals>`.

By default Routinator will stay attached to your terminal and log to standard
error. You can provide the :option:`--detach` option to run it in the background
instead, in which case logging information is written to syslog. To learn more
about what kind of information is returned and how to influence what is logged
and where, refer to the :ref:`Logging <doc_routinator_logging>` section.

The HTTP Service
----------------

In addition to the various :ref:`VRP output formats
<doc_routinator_output_formats>`, Routinator's HTTP server also provides an API,
a :ref:`user interface <doc_routinator_ui>` and :ref:`monitoring endpoints
<doc_routinator_monitoring>`. The server is not enabled by default for security
reasons, nor does it have a default host or port. This service is intended to
run on your internal network and doesn't offer HTTPS natively. If this is a
requirement, you can for example run Routinator behind a :ref:`reverse proxy
<doc_routinator_reverse_proxy>`.

In order to start the HTTP server at 192.0.2.13 and 2001:0DB8::13 on port 8323,
run:

.. code-block:: text

   routinator server --http 192.0.2.13:8323 --http [2001:0DB8::13]:8323

After fetching and verifying all RPKI data, paths are available for each 
:ref:`VRP output format <doc_routinator_output_formats>`. For example, at the
``/csv`` path you can fetch a list of all VRPs in CSV format.

.. code-block:: text

   curl http:///192.0.2.13:8323/csv

These paths accept selector expressions to limit the VRPs returned in the form
of a query string. The field ``select-asn`` can be used to select ASNs and
the field ``select-prefix`` can be used to select prefixes. The fields can be
repeated multiple times. 

For example, to only show the VRPs authorising AS196615 use:

.. code-block:: text

   curl http:///192.0.2.13:8323/csv?select-asn=196615


API Endpoints
"""""""""""""

.. versionchanged:: 0.9
   The :command:`/api/v1/status` path
.. versionadded:: 0.9
   The :command:`/json-delta` path

The service supports GET requests with the following paths:

:command:`/api/v1/status`
     Returns exhaustive information in JSON format on all trust anchors,
     repositories, RRDP and rsync connections, as well as RTR and HTTP sessions.
     This data set provides the source for the Routinator user interface.

:command:`/api/v1/validity/as-number/prefix`
     Returns a JSON object describing whether the route announcement given by 
     its origin AS Number and address prefix is RPKI valid, invalid, or not 
     found. A complete list of VRPs that caused the result is included.
     
:command:`/validity?asn=as-number&prefix=prefix`
     Same as above but with a more form-friendly calling convention.
     
:command:`/json-delta, /json-delta?sessionsession?serial=serial`
     Returns a JSON object with the changes since the dataset version identified
     by the *session* and *serial* query parameters. If a delta cannot be
     produced from that version, the full data set is returned and the member
     *reset* in the object will be set to *true*. In either case, the members
     *session* and *serial* identify the version of the data set returned and
     their values should be passed as the query parameters in a future request.

     The members *announced* and *withdrawn* contain arrays with route origins
     that have been announced and withdrawn, respectively, since the provided
     session and serial. If *reset* is *true*, the *withdrawn* member is not
     present.

In addition, the :command:`/log` endpoint returns :ref:`logging
<doc_routinator_logging>` information and the :command:`/metrics`,
:command:`/status` and :command:`/version` endpoints provide :ref:`monitoring
<doc_routinator_monitoring>` data.

The RTR Service
---------------

Routinator has a built-in server for the RPKI-to-Router (RTR) protocol. It
supports :RFC:`8210` as well as the older version described in :RFC:`6810`. When
launched as an RTR server, routers with support for route origin validation
(ROV) can connect to Routinator to fetch the processed data. 

.. Tip:: If you would like to run the RTR server as a separate daemon, for
         example because you want to centralise validation and distribute
         processed data to various locations where routers can connect, then
         NLnet Labs provides `RTRTR
         <https://www.nlnetlabs.nl/projects/rpki/rtrtr/>`_.

Like the HTTP server, the RTR server is not started by default, nor does it have
a default host or port. Thus, in order to start the RTR server at 192.0.2.13 and
2001:0DB8::13 on port 3323, run Routinator using the :subcmd:`server` command:

.. code-block:: text

   routinator server --rtr 192.0.2.13:3323 --rtr [2001:0DB8::13]:3323

Please note that port 3323 is not the :abbr:`IANA (Internet Assigned Numbers
Authority)`-assigned default port for the protocol,  which would be 323. But as
this is a privileged port, you would need to be running Routinator as root when
otherwise there is no reason to do that. The application will stay attached to
your terminal unless you provide the :option:`--detach` option.

Communication between Routinator and the router using the RPKI-RTR protocol is
done via plain TCP. Below, there is an explanation how to secure the transport
using either SSH or TLS.

.. _doc_routinator_rtr_secure_transport:

Secure Transports
"""""""""""""""""

These instructions were contributed by `wk on Github
<https://github.com/NLnetLabs/routinator/blob/master/doc/transports.md>`_.

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

4. Restart the OpenSSH server daemon.

5. Set up the router running IOS-XR using this example configuration:

.. code-block:: text

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

.. code-block:: text

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
