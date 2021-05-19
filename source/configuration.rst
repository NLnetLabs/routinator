.. _doc_routinator_configuration:

Configuration
=============

Routinator has a number of default settings, such as the location where files
are stored, the refresh interval and the log level. You can view these
settings by running:

.. code-block:: text

   routinator config

It will return the list of defaults in the same notation that is used by the
optional configuration file, which will be largely similar to this:

.. code-block:: text

    allow-dubious-hosts = false
    dirty = false
    disable-rrdp = false
    disable-rsync = false
    exceptions = []
    expire = 7200
    history-size = 10
    http-listen = []
    log = "default"
    log-level = "WARN"
    max-object-size = 20000000
    refresh = 600
    repository-dir = "/Users/routinator/.rpki-cache/repository"
    retry = 600
    rrdp-fallback-time = 3600
    rrdp-proxies = []
    rrdp-root-certs = []
    rsync-command = "rsync"
    rsync-timeout = 300
    rtr-client-metrics = false
    rtr-listen = []
    rtr-tcp-keepalive = 60
    stale = "reject"
    strict = false
    syslog-facility = "daemon"
    systemd-listen = false
    tal-dir = "/Users/routinator/.rpki-cache/tals"
    unknown-objects = "warn"
    unsafe-vrps = "warn"
    validation-threads = 4

You can override these defaults, as well as configure a great number of
additional options using either command line arguments or via the configuration
file.

.. seealso:: To get an overview of all available options, please refer to the
             :ref:`configuration file <doc_routinator_manpage_configfile>`
             section of the :ref:`doc_routinator_manpage`, which can be also 
             viewed by running :command:`routinator man`.

Using a Configuration File
--------------------------

Routinator can take its configuration from a file. You can specify such a config
file via the :option:`--config` option. If you don’t, Routinator will check if
there is a :file:`$HOME/.routinator.conf` and if it exists, use it. If it
doesn’t exist and there is no :option:`--config` option, the default values are
used.

For specifying configuration options, Routinator uses a `TOML file
<https://github.com/toml-lang/toml>`_. Its entries are named similarly to the
command line options. A complete sample configuration file showing all the
default values can be found in the repository at `etc/routinator.conf.example
<https://github.com/NLnetLabs/routinator/blob/master/etc/routinator.conf.example>`_.

.. Note:: One scenario where a configuration file is required is when you would 
          like to pass certain rsync arguments using the ``rsync-args`` 
          setting, which is not available as a command line option. This is 
          because Routinator will try to find out if your rsync understands the 
          ``--contimeout`` option and set it if possible.

For example, if you want Routinator to refresh every 15 minutes and run as an
RTR server on 192.0.2.13 and 2001:0DB8::13 on port 3323, in addition to
providing an HTTP server on port 9556, simply take the output from
:command:`routinator config` and change the ``refresh``, ``rtr-listen`` and
``http-listen`` values in your favourite text editor:

.. code-block:: text

    allow-dubious-hosts = false
    dirty = false
    disable-rrdp = false
    disable-rsync = false
    exceptions = []
    expire = 7200
    history-size = 10
    http-listen = ["192.0.2.13:9556", "[2001:0DB8::13]:9556"]
    log = "default"
    log-level = "WARN"
    max-object-size = 20000000
    refresh = 900
    repository-dir = "/Users/routinator/.rpki-cache/repository"
    retry = 600
    rrdp-fallback-time = 3600
    rrdp-proxies = []
    rrdp-root-certs = []
    rsync-command = "rsync"
    rsync-timeout = 300
    rtr-client-metrics = false
    rtr-listen = ["192.0.2.13:3323", "[2001:0DB8::13]:3323"]
    rtr-tcp-keepalive = 60
    stale = "reject"
    strict = false
    syslog-facility = "daemon"
    systemd-listen = false
    tal-dir = "/Users/routinator/.rpki-cache/tals"
    unknown-objects = "warn"
    unsafe-vrps = "warn"
    validation-threads = 4

After saving this file as :file:`.routinator.conf` in your home directory, you
can start Routinator with:

.. code-block:: bash

   routinator server

.. _doc_routinator_local_exceptions:

Applying Local Exceptions
-------------------------

In some cases, you may want to override the global RPKI data set with your own
local exceptions. For example, when a legitimate route announcement is
inadvertently flagged as *invalid* due to a misconfigured ROA, you may want to
temporarily accept it to give the operators an opportunity to resolve the
issue.

You can do this by specifying route origins that should be filtered out of the
output, as well as origins that should be added, in a file using JSON notation
according to the :abbr:`SLURM (Simplified Local Internet Number Resource
Management with the RPKI)` standard specified in :RFC:`8416`.

A full example file is provided below. This, along with an empty one is
available in the repository at `/test/slurm
<https://github.com/NLnetLabs/routinator/tree/master/test/slurm>`_.

.. code-block:: json

   {
     "slurmVersion": 1,
     "validationOutputFilters": {
      "prefixFilters": [
        {
         "prefix": "192.0.2.0/24",
         "comment": "All VRPs encompassed by prefix"
        },
        {
         "asn": 64496,
         "comment": "All VRPs matching ASN"
        },
        {
         "prefix": "198.51.100.0/24",
         "asn": 64497,
         "comment": "All VRPs encompassed by prefix, matching ASN"
        }
      ],
      "bgpsecFilters": [
        {
         "asn": 64496,
         "comment": "All keys for ASN"
        },
        {
         "SKI": "Zm9v",
         "comment": "Key matching Router SKI"
        },
        {
         "asn": 64497,
         "SKI": "YmFy",
         "comment": "Key for ASN 64497 matching Router SKI"
        }
      ]
     },
     "locallyAddedAssertions": {
      "prefixAssertions": [
        {
         "asn": 64496,
         "prefix": "198.51.100.0/24",
         "comment": "My other important route"
        },
        {
         "asn": 64496,
         "prefix": "2001:DB8::/32",
         "maxPrefixLength": 48,
         "comment": "My other important de-aggregated routes"
        }
      ],
      "bgpsecAssertions": [
        {
         "asn": 64496,
         "comment" : "My known key for my important ASN",
         "SKI": "<some base64 SKI>",
         "routerPublicKey": "<some base64 public key>"
        }
      ]
     }
   }

Use the :option:`--exceptions` option to refer to your file with local
exceptions. Routinator will re-read that file on every validation run, so you
can simply update the file whenever your exceptions change.
