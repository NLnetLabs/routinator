.. _doc_routinator_initialisation:

Initialisation
==============

Before running Routinator for the first time, you must prepare its working
environment. You do this using the :subcmd:`init` command. This will prepare
both the directory for the local RPKI cache, as well as the Trust Anchor Locator
(TAL) directory.

By default, both directories will be located under ``$HOME/.rpki-cache``, but
you can change their locations via the command line options
:option:`--repository-dir` and :option:`--tal-dir`.

TALs provide hints for the trust anchor certificates to be used both to discover
and validate all RPKI content. The five TALs — one for each Regional Internet
Registry (RIR) — are bundled with Routinator and installed by the :subcmd:`init`
command.

.. WARNING:: Using the TAL from ARIN, the RIR for the United States, Canada as
             well as many Caribbean and North Atlantic islands, requires you to
             read and accept their `Relying Party Agreement
             <https://www.arin.net/resources/manage/rpki/tal/>`_ before you can
             use it. Running the :subcmd:`init` command will provide you with
             instructions.

.. code-block:: text

   routinator init
   Before we can install the ARIN TAL, you must have read
   and agree to the ARIN Relying Party Agreement (RPA).
   It is available at

   https://www.arin.net/resources/manage/rpki/rpa.pdf

   If you agree to the RPA, please run the command
   again with the --accept-arin-rpa option.

Running the :subcmd:`init` command with the :option:`--accept-arin-rpa` option
will create the TAL directory and copy the five Trust Anchor Locator files into
it.

.. code-block:: bash

   routinator init --accept-arin-rpa

If you decide you cannot agree to the ARIN RPA terms, the
:option:`--decline-arin-rpa` option will install all TALs except the one for
ARIN. If, at a later point, you wish to use the ARIN TAL anyway, you can add it
to your current installation using the :option:`--force` option, to force the
installation of all TALs.

Performing a Test Run
---------------------

To see if Routinator has been initialised correctly and your firewall allows the
required connections, it is recommended to perform an initial test run. You can
do this by having Routinator print a validated ROA payload (VRP) list with the
:subcmd:`vrps` subcommand, and using :option:`-v` to increase the log level so
you can verify if Routinator establishes rsync and RRDP connections as expected.

.. code-block:: bash

   routinator -vv vrps

Now, you can see how Routinator connects to the RPKI trust anchors, downloads
the the contents of the repositories to your machine, verifies it and produces a
list of validated ROA payloads in the default CSV format to standard output.
Because it is expected that the state of the entire RPKI is not perfect as all
times, you may see several warnings during the process about objects that are
either stale or failed cryptographic verification. From a cold start, this
process will take a couple of minutes.

.. code-block:: text

    routinator -vv vrps
    rsyncing from rsync://repository.lacnic.net/rpki/.
    rsync://repository.lacnic.net/rpki: Running command "rsync" "--timeout=300" "-rltz" "--delete" "rsync://repository.lacnic.net/rpki/" "/Users/alex/.rpki-cache/repository/rsync/repository.lacnic.net/rpki/"
    Found valid trust anchor https://rpki.ripe.net/ta/ripe-ncc-ta.cer. Processing.
    RRDP https://rrdp.ripe.net/notification.xml: Updating server
    RRDP https://rrdp.ripe.net/notification.xml: updating from snapshot.
    Found valid trust anchor https://rpki.afrinic.net/repository/AfriNIC.cer. Processing.
    RRDP https://rrdp.afrinic.net/notification.xml: Updating server
    RRDP https://rrdp.afrinic.net/notification.xml: updating from snapshot.
    Found valid trust anchor https://tal.apnic.net/apnic.cer. Processing.
    RRDP https://rrdp.apnic.net/notification.xml: Updating server
    RRDP https://rrdp.apnic.net/notification.xml: updating from snapshot.
    Found valid trust anchor https://rrdp.arin.net/arin-rpki-ta.cer. Processing.
    RRDP https://rrdp.arin.net/notification.xml: Updating server
    RRDP https://rrdp.arin.net/notification.xml: updating from snapshot.
    rsync://repository.lacnic.net/rpki: successfully completed.
    Found valid trust anchor rsync://repository.lacnic.net/rpki/lacnic/rta-lacnic-rpki.cer. Processing.
    rsyncing from rsync://rpki-repo.registro.br/repo/.
    rsync://rpki-repo.registro.br/repo: Running command "rsync" "--timeout=300" "-rltz" "--delete" "rsync://rpki-repo.registro.br/repo/" "/Users/alex/.rpki-cache/repository/rsync/rpki-repo.registro.br/repo/"
    rsync://rpki-repo.registro.br/repo: successfully completed.
    RRDP https://rrdp.rpki.nlnetlabs.nl/rrdp/notification.xml: Updating server
    RRDP https://rrdp.rpki.nlnetlabs.nl/rrdp/notification.xml: updating from snapshot.
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