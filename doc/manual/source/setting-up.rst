.. Important:: **With Routinator 0.12.0 and newer, initialisation to accept 
               the ARIN Relying Party Agreement is no longer required.** By 
               default, Routinator is set up to fetch and validate all RPKI
               data needed for production environments.

Setting Up
==========

Routinator can run interactively or as a service that periodically fetches
RPKI data, verifies it and makes the resulting data set available through the
built-in HTTP and RPKI-to-Router (RTR) servers. 

If you have installed Routinator using a package from our software package
repository, the application is configured to run as a system service with the
user *routinator*. We have pre-installed a :doc:`configuration
file<configuration>` located in ``/etc/routinator/routinator.conf``
explicitly setting the RPKI cache directory and enabling the HTTP and RTR
servers on localhost. 

If you have built Routinator using Cargo, by default the RPKI cache directory
will be created under :file:`$HOME/.rpki-cache/repository`. You can change
the location using the :option:`--repository-dir` option. The :doc:`HTTP
service<http-service>` and :doc:`RTR service<rtr-service>` must be started
explicitly using the command line options :option:`--http` and
:option:`--rtr`, respectively. These options can be set using a
:doc:`configuration file<configuration>` as well. 

Trust Anchor Locators
---------------------

Fetching data is done by connecting to the :term:`Trust Anchor Locators
(TALs) <Trust Anchor Locator (TAL)>` of the five Regional Internet Registries
(RIRs): AFRINIC, APNIC, ARIN, LACNIC and RIPE NCC. TALs provide hints for
the trust anchor certificates to be used both to discover and validate all
RPKI content. **By default, Routinator will be set up for use in production
environments and run with the production TALs of the five RIRs.**

Some RIRs and third parties also provide separate TALs for testing purposes,
allowing operators to gain experience with using RPKI in a safe environment.
Both the production and testbed TALs are bundled with Routinator and can be
enabled and disabled using command line and configuration file options.

Run the following command to list all available TALs:

.. code-block:: text

    routinator --tal=list
    
This displays the following overview:
    
.. code-block:: text
    
     .---- --rir-tals
     |  .- --rir-test-tals
     V  V
     
     X      afrinic             AFRINIC production TAL
     X      apnic               APNIC production TAL
     X      arin                ARIN production TAL
     X      lacnic              LACNIC production TAL
     X      ripe                RIPE production TAL
        X   apnic-testbed       APNIC RPKI Testbed
        X   arin-ote            ARIN Operational Test and Evaluation Environment
        X   ripe-pilot          RIPE NCC RPKI Test Environment
            nlnetlabs-testbed   NLnet Labs RPKI Testbed

You can influence which TALs Routinator uses with the :option:`--tal` option,
which can be combined with the :option:`--no-rir-tals` option to leave out
all RIR production TALs, as well as the :option:`--extra-tals-dir` option to
specify a directory containing extra TALs to use.

For example, if you want to add the RIPE NCC RPKI Test Environment to the
default TAL set, run:

.. code-block:: text

    routinator --tal=ripe-pilot

If you want to run Routinator without any of the production TALs and only
fetch data from the ARIN Operational Test and Evaluation Environment, run:

.. code-block:: text

    routinator --no-rir-tals --tal=arin-ote

Lastly, if you would like to use a TAL that isn't bundled with Routinator you
can place it in a directory of your choice, for example
:file:`/var/lib/routinator/tals`, and refer to it by running:

.. code-block:: text

    routinator --extra-tals-dir="/var/lib/routinator/tals"

Routinator will use all files in this directory with an extension of *.tal*
as TALs. These files need to be in the format described by :rfc:`8630`. Note
that Routinator will use all TALs provided. That means that if a TAL in this
directory is one of the bundled TALs, then these resources will be validated
twice.

.. versionadded:: 0.9.0
   :option:`--list-tals`, :option:`--rir-tals`, :option:`--rir-test-tals`, 
   :option:`--tal` and :option:`--skip-tal`
.. deprecated:: 0.9.0
   ``--decline-arin-rpa``, use :option:`--skip-tal` instead
.. versionadded:: 0.12.0
   :option:`--extra-tals-dir`
.. deprecated:: 0.12.0
   The ``init`` subcommand

Verifying Installation
----------------------

You should verify if Routinator has been initialised correctly and your
firewall allows the required outbound connections on ports 443 and 873. From
a cold start, it will take ten to fifteen minutes to do the first validation
run that builds up the validated cache. Subsequent runs will be much faster,
because only the changes between the repositories and the validated cache
need to be processed.

If you have installed Routinator from a package and run it as a service, you
can check the status using:

.. code-block:: bash

   sudo systemctl status routinator

And check the logs using:

.. code-block:: bash

   sudo journalctl --unit=routinator

.. Important:: Because it is expected that the state of the entire RPKI is not 
               perfect as all times, you may see several warnings about objects
               that are either stale or failed cryptographic verification, or
               repositories that are temporarily unavailable. 

If you have built Routinator using Cargo it is recommended to perform an
initial test run. You can do this by having Routinator print a validated ROA
payload (VRP) list with the :subcmd:`vrps` subcommand, and using :option:`-v`
twice to increase the :doc:`log level<logging>` to *debug*:

.. code-block:: bash

   routinator -vv vrps

Now, you can see how Routinator connects to the RPKI trust anchors, downloads
the the contents of the repositories to your machine, verifies it and
produces a list of VRPs in the default CSV format to standard output. 

.. code-block:: text

      Using the following TALs:
      * afrinic
      * apnic
      * arin
      * lacnic
      * ripe
      Found valid trust anchor https://rpki.ripe.net/ta/ripe-ncc-ta.cer. Processing.
      Found valid trust anchor https://rrdp.arin.net/arin-rpki-ta.cer. Processing.
      Found valid trust anchor https://rpki.afrinic.net/repository/AfriNIC.cer. Processing.
      Found valid trust anchor https://rrdp.lacnic.net/ta/rta-lacnic-rpki.cer. Processing.
      Found valid trust anchor https://rpki.apnic.net/repository/apnic-rpki-root-iana-origin.cer. Processing.
      RRDP https://rrdp.ripe.net/notification.xml: updating from snapshot.
      RRDP https://rrdp.arin.net/notification.xml: updating from snapshot.
      RRDP https://rrdp.apnic.net/notification.xml: updating from snapshot.
      RRDP https://rrdp.lacnic.net/rrdp/notification.xml: updating from snapshot.
      RRDP https://rrdp.afrinic.net/notification.xml: updating from snapshot.
      RRDP https://rrdp.apnic.net/notification.xml: snapshot update completed.
      RRDP https://rpki-rrdp.us-east-2.amazonaws.com/rrdp/08c2f264-23f9-49fb-9d43-f8b50bec9261/notification.xml: updating from snapshot.
      RRDP https://rpki-rrdp.us-east-2.amazonaws.com/rrdp/08c2f264-23f9-49fb-9d43-f8b50bec9261/notification.xml: snapshot update completed.
      RRDP https://rrdp.ripe.net/notification.xml: snapshot update completed.
      RRDP https://rpki.akrn.net/rrdp/notification.xml: updating from snapshot.
      RRDP https://rpki.akrn.net/rrdp/notification.xml: snapshot update completed.
      RRDP https://rpki-rrdp.us-east-2.amazonaws.com/rrdp/bd48a1fa-3471-4ab2-8508-ad36b96813e4/notification.xml: updating from snapshot.
      RRDP https://rpki-rrdp.us-east-2.amazonaws.com/rrdp/bd48a1fa-3471-4ab2-8508-ad36b96813e4/notification.xml: snapshot update completed.
      RRDP https://rpki.admin.freerangecloud.com/rrdp/notification.xml: updating from snapshot.
      RRDP https://rpki.admin.freerangecloud.com/rrdp/notification.xml: snapshot update completed.
      RRDP https://rpki.cnnic.cn/rrdp/notify.xml: updating from snapshot.
      RRDP https://rrdp.lacnic.net/rrdp/notification.xml: snapshot update completed.
      ...
      ASN,IP Prefix,Max Length,Trust Anchor
      AS137884,103.116.116.0/23,23,apnic
      AS9003,91.151.112.0/20,20,ripe
      AS38553,120.72.19.0/24,24,apnic
      AS58045,37.209.242.0/24,24,ripe
      AS9583,202.177.175.0/24,24,apnic
      AS50629,2a0f:ba80::/29,29,ripe
      AS398085,2602:801:a008::/48,48,arin
      AS21050,83.96.22.0/24,24,ripe
      AS55577,183.82.223.0/24,24,apnic
      AS44444,157.167.73.0/24,24,ripe
      AS197695,194.67.97.0/24,24,ripe
      ...