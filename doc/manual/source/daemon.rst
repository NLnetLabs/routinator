Running as a Daemon
===================

Routinator can run as a service that periodically fetches RPKI data, verifies
it and makes the resulting data set available through the built-in HTTP and
RPKI-to-Router (RTR) servers.

If you have installed Routinator through our software package repository, the
HTTP and RTR servers are enabled by default via the :ref:`pre-installed
configuration file <configuration:routinator installed from a package>`.
However, they are only available on localhost for security reasons. You will
have to explicitly change these options to make the services available to
other network devices.

If you have built Routinator using Cargo, no servers are enabled by default
at all. From the command line you can start Routinator as a daemon using the
:subcmd:`server` subcommand. Use the :option:`--http` command line option or
the :term:`http-listen` configuration file option to start the HTTP server.
To enable the RTR server, use the :option:`--rtr` command line option or the
:term:`rtr-listen` option in the configuration file. Of course you also start
both. 

HTTPS and secure transports for RTR are supported as well. Please read the
:doc:`http-service` and :doc:`rtr-service` sections for details.

.. Note:: Both servers will only start serving data once the first validation
          run has completed. Routinator will not reread the trust anchor 
          locators after it has started the service. Thus, if you add or 
          change a TAL you must restart Routinator or send it a
          :ref:`SIGUSR1 <manual-page:signals>`.

Using 192.0.2.13 as an example IPv4 address, enter the following command to
start Routinator with the HTTP server listening on port 8323 and the RTR
server on port 3323:

.. code-block:: text

   routinator server --http 192.0.2.13:8323 --rtr 192.0.2.13:3323
   
Make sure IPv6 addresses are in square brackets, e.g.:

.. code-block:: text

   routinator server --rtr [2001:0DB8::13]:3323 --rtr 192.0.2.13:3323

By default Routinator will stay attached to your terminal and log to standard
error. You can provide the :option:`--detach` option to run it in the
background instead, in which case logging information is written to syslog.
To learn more about what kind of information is returned and how to influence
what is logged and where, refer to the :doc:`logging` section.


.. Attention:: On Linux systems there is an overlap between IPv4 and IPv6. 
               You can’t bind to all interfaces on both address families,
               i.e. ``0.0.0.0`` and ``[::]``, as it will result in a 
               *‘address already in use’* error. Instead, to listen to both
               IPv4 and IPv6 you can simply enter:
                
               .. code-block:: text

                  routinator server --rtr [::]:3323
