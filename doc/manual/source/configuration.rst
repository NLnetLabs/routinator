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
command line. However, there are several considerations with regards to how
you've installed and how you intend to use Routinator, which we'll cover
below.

Routinator Installed From a Package
-----------------------------------

The installation script will run as the user *routinator* and refer to the
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

Routinator Built with Cargo
---------------------------

If you have built Routinator using Cargo, you have made your own decisions
with regards to the user that it runs as and the privileges it has. There is
no default configuration file, as it is your choice if you want to use one.

If you run Routinator without referring to a configuration file it will check
if there is a :file:`$HOME/.routinator.conf` file and if it exists, use it.
If no configuration file is available, the default values are used.

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
to download several gigabytes of data, which usually takes about ten minutes
to complete. During this time all services will be unavailable.

Note that your routers should be configured to have a secondary relying party
instance available at all times.
