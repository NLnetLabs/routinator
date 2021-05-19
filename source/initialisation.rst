.. _doc_routinator_initialisation:

Initialisation
==============

Before running Routinator for the first time, you must prepare its working
environment. You do this using the :subcmd:`init` subcommand. This will prepare
both the directory for the local RPKI cache, as well as the directory where the
Trust Anchor Locator (TAL) files reside.

By default, both directories will be located under ``$HOME/.rpki-cache`` but
you can change their locations via the command line options
:option:`--repository-dir` and :option:`--tal-dir`.

Trust Anchor Locators
---------------------

.. versionadded:: 0.9
   :option:`--list-tals`, :option:`--rir-tals`, :option:`--rir-test-tals`, 
   :option:`--tal` and :option:`--skip-tal`
.. deprecated:: 0.9
   ``--decline-arin-rpa``, use :option:`--skip-tal` instead

Trust Anchor Locators (TALs) provide hints for the trust anchor certificates to
be used both to discover and validate all RPKI content. There are five TALs, one
for each Regional Internet Registry (RIR). For production environments these are
the only five you will ever need to fetch and validate all available RPKI data.

Some RIRs and third parties also provide separate TALs for testing purposes,
allowing operators to gain experience with using RPKI in a safe environment.
Both the production and testbed TALs are bundled with Routinator and can be
installed with the :subcmd:`init` command. 

To get an overview of all available TALs use the :option:`--list-tals` option:

.. code-block:: text

    routinator init --list-tals
    
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

Preparing for Production Environments
"""""""""""""""""""""""""""""""""""""

.. WARNING:: Using the TAL from ARIN requires you to read and accept their 
             `Relying Party Agreement
             <https://www.arin.net/resources/manage/rpki/tal/>`_ before you can
             use it. Running the :subcmd:`init` subcommand will provide you with
             instructions.

In the most common scenario, you will want to install the TALs of the five RIRs.
To do this, run the following command:

.. code-block:: text

   routinator init --rir-tals
   
This will return the following message:
   
.. code-block:: text   
   
   Before we can install the ARIN TAL, you must have read
   and agree to the ARIN Relying Party Agreement (RPA).
   It is available at

   https://www.arin.net/resources/manage/rpki/rpa.pdf

   If you agree to the RPA, please run the command
   again with the --accept-arin-rpa option.

Running the :subcmd:`init` command with the :option:`--accept-arin-rpa` option
added will create the TAL directory and copy the five Trust Anchor Locator files
into it:

.. code-block:: bash

   routinator init --rir-tals --accept-arin-rpa

If you decide you cannot agree to the ARIN RPA terms, you can use the
:option:`--skip-tal` option to exclude the TAL. If, at a later point, you wish
to include the ARIN TAL you can add it to your current installation using the
:option:`--force` option, to force the installation of all TALs.

Preparing for Test Environments
"""""""""""""""""""""""""""""""

To install all of the TALs for the various test environments, you can use the
:option:`--rir-test-tals` option. However, in most cases you will want to
install a specific one, using the :option:`--tal` option. 

For example, to add the TAL for the `ARIN Operational Test and Evaluation
Environment <https://www.arin.net/reference/tools/testing/#rpki>`_ to an already
initialised Routinator, enter:

.. code-block:: bash

   routinator init --force --tal arin-ote

Performing a Test Run
---------------------

To see if Routinator has been initialised correctly and your firewall allows the
required outbound connections on ports 443 and 873, it is recommended to perform
an initial test run. You can do this by having Routinator print a validated ROA
payload (VRP) list with the :subcmd:`vrps` subcommand, and using :option:`-v`
twice to increase the :ref:`log level <doc_routinator_logging>` to *debug*. This
way you can verify if Routinator establishes connections as expected:

.. code-block:: bash

   routinator -vv vrps

Now, you can see how Routinator connects to the RPKI trust anchors, downloads
the the contents of the repositories to your machine, verifies it and produces a
list of validated ROA payloads in the default CSV format to standard output.
Because it is expected that the state of the entire RPKI is not perfect as all
times, you may see several warnings during the process about objects that are
either stale or failed cryptographic verification, or repositories that are
temporarily unavailable. 

From a cold start, this process will take a couple of minutes. Subsequent
verification runs will be much faster, because only the changes between the
repositories and the local cache need to be processed:

.. code-block:: text

    RRDP https://rrdp.ripe.net/notification.xml: Tree has 0 entries.
    RRDP https://rrdp.ripe.net/notification.xml: updating from snapshot.
    Found valid trust anchor https://rpki.afrinic.net/repository/AfriNIC.cer. Processing.
    Found valid trust anchor https://rpki.apnic.net/repository/apnic-rpki-root-iana-origin.cer. Processing.
    RRDP https://rrdp.afrinic.net/notification.xml: Tree has 0 entries.
    RRDP https://rrdp.afrinic.net/notification.xml: updating from snapshot.
    RRDP https://rrdp.apnic.net/notification.xml: Tree has 0 entries.
    RRDP https://rrdp.apnic.net/notification.xml: updating from snapshot.
    RRDP https://rrdp.afrinic.net/notification.xml: snapshot update completed.
    Found valid trust anchor https://rrdp.arin.net/arin-rpki-ta.cer. Processing.
    RRDP https://rrdp.arin.net/notification.xml: Tree has 0 entries.
    RRDP https://rrdp.arin.net/notification.xml: updating from snapshot.
    rsync://repository.lacnic.net/rpki/: successfully completed.
    Found valid trust anchor https://rrdp.lacnic.net/ta/rta-lacnic-rpki.cer. Processing.
    RRDP https://rrdp.lacnic.net/rrdp/notification.xml: Tree has 0 entries.
    RRDP https://rrdp.lacnic.net/rrdp/notification.xml: updating from snapshot.
    RRDP https://rrdp.arin.net/notification.xml: snapshot update completed.
    RRDP https://rrdp.sub.apnic.net/notification.xml: Tree has 0 entries.
    RRDP https://rrdp.sub.apnic.net/notification.xml: updating from snapshot.
    RRDP https://rrdp.ripe.net/notification.xml: snapshot update completed.
    RRDP https://rrdp.sub.apnic.net/notification.xml: snapshot update completed.
    RRDP https://rpki-repo.registro.br/rrdp/notification.xml: Tree has 0 entries.
    RRDP https://rpki-repo.registro.br/rrdp/notification.xml: updating from snapshot.
    RRDP https://rrdp.twnic.tw/rrdp/notify.xml: Tree has 0 entries.
    RRDP https://rrdp.twnic.tw/rrdp/notify.xml: updating from snapshot.
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