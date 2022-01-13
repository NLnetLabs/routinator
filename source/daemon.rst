Running as a Daemon
===================

Routinator can run as a service that periodically fetches RPKI data, verifies it
and makes the resulting data set available through the built-in HTTP server and
via the RTR protocol. 

If you have installed Routinator through the `NLnet Labs software package
repository <https://packages.nlnetlabs.nl>`_, the RTR and HTTP servers are only
available on localhost for security reasons. You will have to explicitly change
this setting in the :doc:`configuration file<configuration>` to make the
services available to other machines.

When you have installed Routinator using Cargo, no servers are enbled by default
at all. You can start the Routinator service using the :subcmd:`server`
subcommand and specifying to start the HTTP server with the :option:`--http`
option and the RTR server with the :option:`--rtr` option. You can of course
also start both.

.. Note:: Routinator will not reread the trust anchor locators after it has
          started the service. Thus, if you add or change a TAL you must restart
          Routinator or send it a :ref:`SIGUSR1 <manual-page:signals>`.

If you're running Routinator on the IPv4 address 192.0.2.13 and you want to
start the HTTP server on port 8323 and the RTR server on port 3323, run:

.. code-block:: text

   routinator server --http 192.0.2.13:8323 --rtr 192.0.2.13:3323
   
Make sure IPv6 addresses are in square brackets, e.g.:

.. code-block:: text

   routinator server --rtr [2001:0DB8::13]:3323 --rtr 192.0.2.13:3323

Both servers will only start serving data once the first validation run has
completed. 

By default Routinator will stay attached to your terminal and log to standard
error. You can provide the :option:`--detach` option to run it in the background
instead, in which case logging information is written to syslog. To learn more
about what kind of information is returned and how to influence what is logged
and where, refer to the :doc:`logging` section.


.. Attention::  On Linux systems there is an overlap between IPv4 and IPv6. You
                can’t bind to all interfaces on both address families on the
                same port. For example, this command will result in a  *‘address
                already in use’* error: 

                .. code-block:: text

                   routinator server --rtr 0.0.0.0:3323 --rtr [::]:3323
                   
                Instead, to listen to both IPv4 and IPv6 you can simply enter:
                
                .. code-block:: text

                   routinator server --rtr [::]:3323