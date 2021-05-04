.. _doc_routinator_data_processing:

Data Processing
===============

Fetching
--------

.. versionadded:: 0.9
   Fallback from RRDP to rsync with :option:`--rrdp-fallback-time`

There are two protocols in use to transport RPKI data: rsync and the RPKI
Repository Delta Protocol (RRDP), which relies on HTTPS. RRDP was designed to be
the successor to rsync in the RPKI. As almost all RPKI repositories currently
support both protocols, Routinator will prefer RRDP if available. 

When traversing the RPKI tree, Routinator will find several pointers to child
publication points, such as the ones operated by National Internet Registries
and organisations running delegated RPKI. Each pointer explicitly states if RRDP
is supported in addition to rsync. 

If an RRDP endpoint is unavailable but it has worked in the past, Routinator
will assume this is a transient problem. It will retry using RRDP for up to 60
minutes since the last successful update, during which it will rely on the
locally cached data for this repository. After this time, Routinator will try to
use rsync to fetch the data instead. To spread out load on the rsync server, the
exact moment fallback happens is picked randomly between the refresh time and
the :option:`--rrdp-fallback-time` value. If rsync communication is
unsuccessful too, the local cache is used until the objects go stale and
ultimately expire. 

Routinator will fetch new RPKI data ten minutes after the last successful update
has finished. The interval can be changed using the :option:`--refresh` option.
It is possible that it takes very long to update a repository due to
temporary network problems. To ensure a slow repository doesn't stop the entire
update process from completing, Routinator has a timeout for stalled
connections. For RRDP, this timeout is implemented as an HTTP request timeout.
For rsync, the timeout is around the spawned rsync process. The default is five
minutes for both and can be changed via the :option:`--rsync-timeout` and
:option:`--rrdp-timeout` options.

Storing
-------

.. versionadded:: 0.9
   The *store* and the :option:`--fresh` option

To be resistant against accidental or malicious errors in the data published by
repositories, Routinator retains two separate data sets: one that keeps the data
of all publication points as it was received from their remote repository, and
another – which we call the *store* – keeps the most recent data of a given RPKI
publication point that was found to be correctly published. 

Data is only transferred into the store if a manifest was found to be valid and
if all files mentioned on the manifest are present and have the correct hash.
Otherwise the data for the publication point already present in the store will
be used for validation.

If you ever want or need to clear all stored data, you can use the
:option:`--fresh` option. This will be like starting Routinator for the very
first time:

.. code-block:: text

    routinator --fresh vrps
