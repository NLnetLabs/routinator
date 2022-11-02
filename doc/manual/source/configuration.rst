.. Important:: **With Routinator 0.12.0 and newer, initialisation to accept 
               the ARIN Relying Party Agreement (RPA) is no longer 
               required.** The RPA `has been updated 
               <https://www.arin.net/announcements/20220929/>`_ to allow the 
               ARIN TAL to be embedded in Relying Party software. By 
               default, Routinator is now set up to fetch and validate all 
               RPKI data needed for production environments.

Configuration
=============

Routinator has a large number of configuration options, but in most cases
running it with the defaults will work just fine. You can specify options as
:ref:`command line arguments <manual-page:options>`, but you can also use a
:ref:`configuration file <manual-page:configuration file>`.

Routinator uses the `TOML format <https://github.com/toml-lang/toml>`_ for
specifying options in the configuration file. Its entries are named similarly
to the command line options. A complete sample configuration file showing all
the default values can be found in the `repository
<https://github.com/NLnetLabs/routinator/blob/master/etc/routinator.conf.example>`_.

Routinator can run as a daemon but you can also use it interactively from the
command line. There are several considerations with regards to how you've
installed and how you intend to use Routinator, which we'll cover below.

Setup When Installed From a Package
-----------------------------------

The installation script will set up Routinator to run as the user
*routinator* and be configured to start at boot. Routinator will use the
configuration file :file:`/etc/routinator/routinator.conf` which contains the
following pre-configured options:

.. code-block:: toml

   repository-dir = "/var/lib/routinator/rpki-cache"
   rtr-listen = ["127.0.0.1:3323"]
   http-listen = ["127.0.0.1:8323"]

For security reasons the HTTP and RTR server will only listen on localhost,
so you will have to change these values to make them accessible to other
devices on your network.

The service script that starts Routinator uses the :option:`--config` option
to explicitly refer to this configuration file, so any desired changes should
be made here. If you would like to know what default settings Routinator runs
with in addition to the settings in the config file, you can check with the
:subcmd:`config` subcommand:

.. code-block:: bash

   routinator --config /etc/routinator/routinator.conf config

This output will also provide you with the correct syntax in case you want to
make changes.

.. Important:: Once you have started Routinator as a system service you 
               should not invoke :doc:`interactive<interactive>` validation 
               runs from the command line using ``routinator vrps``. If there
               is specific information you would like to have from 
               Routinator, you should retrieve it via the 
               :doc:`user interface<user-interface>` or one of the 
               :doc:`HTTP endpoints<http-service>`.

Setup When Built with Cargo
---------------------------

If you have built Routinator using Cargo, you have made your own decisions
with regards to the user that it runs as and the privileges it has. There is
no default configuration file, as it is your choice if you want to use one.

If you run Routinator without referring to a configuration file it will check
if the file :file:`$HOME/.routinator.conf` exists and if it does, use it.
If no configuration file is available, the default values are used.

You can specify the location of the RPKI cache directory using the
:option:`--repository-dir` option. If you don't, one will be created in the
default location :file:`$HOME/.rpki-cache/repository`. The :doc:`HTTP
service<http-service>` and :doc:`RTR service<rtr-service>` must be started
explicitly using the command line options :option:`--http` and
:option:`--rtr`, respectively, or via the configuration file. 

You can view the default settings Routinator runs with using:

.. code-block:: text

   routinator config

It will return the list of defaults in the same notation that is used by the
:ref:`configuration file <manual-page:configuration file>`, which will be
largely similar to this and can serve as a starting point for making your
own:

.. code-block:: toml

      allow-dubious-hosts = false
      dirty = false
      disable-rrdp = false
      disable-rsync = false
      enable-bgpsec = false
      exceptions = []
      expire = 7200
      history-size = 10
      http-listen = []
      http-tls-listen = []
      log = "default"
      log-level = "WARN"
      max-ca-depth = 32
      max-object-size = 20000000
      refresh = 600
      repository-dir = "/Users/routinator/.rpki-cache/repository"
      retry = 600
      rrdp-fallback-time = 3600
      rrdp-max-delta-count = 100
      rrdp-proxies = []
      rrdp-root-certs = []
      rrdp-timeout = 300
      rsync-command = "rsync"
      rsync-timeout = 300
      rtr-client-metrics = false
      rtr-listen = []
      rtr-tcp-keepalive = 60
      rtr-tls-listen = []
      stale = "reject"
      strict = false
      syslog-facility = "daemon"
      systemd-listen = false
      unknown-objects = "warn"
      unsafe-vrps = "accept"
      validation-threads = 10

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
    
      .---- RIR TALs
      |  .- RIR test TALs
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
   The ``init`` subcommand, :option:`--list-tals`

Using Tmpfs for the RPKI Cache
------------------------------

The full RPKI data set consists of hundreds of thousands of small files. This
causes a considerable amount of disk I/O with each validation run. If this is
undesirable in your setup, you can choose to store the cache in volatile
memory using the `tmpfs file system
<https://www.kernel.org/doc/html/latest/filesystems/tmpfs.html>`_.

If you have installed Routinator using a package, by default the RPKI cache
directory will be :file:`/var/lib/routinator/rpki-cache`, so we'll use that
as an example. Note that the directory you choose must exist before the mount
can be done. You should allocate at least 3GB for the cache, but giving it
4GB will allow ample margin for future growth:

.. code-block:: bash

    sudo mount -t tmpfs -o size=4G tmpfs /var/lib/routinator/rpki-cache

*Tmpfs* will behave just like a regular disk, so if it runs out of space
Routinator will do a clean crash, stopping validation, the API, HTTP server
and most importantly the RTR server, ensuring that no stale data will be
served to your routers. 

Also keep in mind that every time you restart the machine, the contents of
the *tmpfs* file system will be lost. This means that Routinator will have to
rebuild its cache from scratch. This is not a problem, other than it having
to download several hundred megabytes of data, which usually takes about ten
minutes to complete. During this time all services will be unavailable.

Note that your routers should be configured to have a secondary relying party
instance available at all times.

Verifying Configuration
-----------------------

You should verify if Routinator has been configured correctly and your
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
               perfect at all times, you may see several warnings about objects
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

      [INFO] Using the following TALs:
      [INFO]   * afrinic
      [INFO]   * apnic
      [INFO]   * arin
      [INFO]   * lacnic
      [INFO]   * ripe
      [DEBUG] Found valid trust anchor https://rpki.ripe.net/ta/ripe-ncc-ta.cer. Processing.
      [DEBUG] Found valid trust anchor https://rrdp.lacnic.net/ta/rta-lacnic-rpki.cer. Processing.
      [DEBUG] Found valid trust anchor https://rpki.afrinic.net/repository/AfriNIC.cer. Processing.
      [DEBUG] Found valid trust anchor https://rpki.apnic.net/repository/apnic-rpki-root-iana-origin.cer. Processing.
      [DEBUG] Found valid trust anchor https://rrdp.arin.net/arin-rpki-ta.cer. Processing.
      [DEBUG] RRDP https://rrdp.ripe.net/notification.xml: updating from snapshot.
      [DEBUG] RRDP https://rrdp.lacnic.net/rrdp/notification.xml: updating from snapshot.
      [DEBUG] RRDP https://rrdp.apnic.net/notification.xml: updating from snapshot.
      [DEBUG] RRDP https://rrdp.afrinic.net/notification.xml: updating from snapshot.
      [DEBUG] RRDP https://rrdp.arin.net/notification.xml: updating from snapshot.
      [DEBUG] RRDP https://rrdp.apnic.net/notification.xml: snapshot update completed.
      [DEBUG] RRDP https://rpki-rrdp.us-east-2.amazonaws.com/rrdp/08c2f264-23f9-49fb-9d43-f8b50bec9261/notification.xml: updating from snapshot.
      [DEBUG] RRDP https://rpki-rrdp.us-east-2.amazonaws.com/rrdp/08c2f264-23f9-49fb-9d43-f8b50bec9261/notification.xml: snapshot update completed.
      [DEBUG] RRDP https://rpki.akrn.net/rrdp/notification.xml: updating from snapshot.
      [DEBUG] RRDP https://rpki.akrn.net/rrdp/notification.xml: snapshot update completed.
      [DEBUG] RRDP https://rpki.admin.freerangecloud.com/rrdp/notification.xml: updating from snapshot.
      [DEBUG] RRDP https://rpki.admin.freerangecloud.com/rrdp/notification.xml: snapshot update completed.
      [DEBUG] RRDP https://rpki.cnnic.cn/rrdp/notify.xml: updating from snapshot.
      [DEBUG] RRDP https://rrdp.ripe.net/notification.xml: snapshot update completed.
      [DEBUG] RRDP https://0.sb/rrdp/notification.xml: updating from snapshot.
      [DEBUG] RRDP https://0.sb/rrdp/notification.xml: snapshot update completed.
      [DEBUG] RRDP https://rrdp.sub.apnic.net/notification.xml: updating from snapshot.
      [DEBUG] RRDP https://rrdp.sub.apnic.net/notification.xml: snapshot update completed.
      [DEBUG] RRDP https://rpki.roa.net/rrdp/notification.xml: updating from snapshot.
      [DEBUG] RRDP https://rpki.roa.net/rrdp/notification.xml: snapshot update completed.
      [DEBUG] RRDP https://rrdp.rp.ki/notification.xml: updating from snapshot.
      [DEBUG] RRDP https://rpki.cnnic.cn/rrdp/notify.xml: snapshot update completed.
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