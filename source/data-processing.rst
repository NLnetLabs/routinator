.. _doc_routinator_data_processing:

Data Processing
===============

Fetching
--------

There are two protocols in use to transport RPKI data: rsync and the RPKI
Repository Delta Protocol (RRDP), which relies on HTTPS. RRDP was designed to be
the successor to rsync. As almost all RPKI repositories currently support both
protocols, Routinator will prefer RRDP if available. 

When traversing the RPKI tree, Routinator will find several pointers to child
publication points, such as the ones operated by National Internet Registries
and organisations running delegated RPKI. Each pointer explicitly states if RRDP
is supported in addition to rsync. 

If an RRDP endpoint is unavailable but it has worked in the past, Routinator
will assume this is a transient problem. It will retry using RRDP for 60 minutes
since the last successful update, during which it will rely on the locally
cached data for this repository. After this time, Routinator will try to use
rsync to fetch the data instead. If this is unsuccessful too, the local cache is
used until the objects go stale and ultimately expire. The fallback time can be
changed using the :option:`--rrdp-fallback-time` option.

Routinator will fetch new RPKI data ten minutes after the last successful update
has finished. The interval can be changed using the :option:`--refresh` option.
It is possible that temporary network problems cause a repository to be very
slow to update. To ensure a slow repository doesn't stop the entire update
process from completing, Routinator has a timeout of five minutes for stalled
connections. 

Storing
-------

To be resistant against accidental or malicious errors in the data published by
repositories, Routinator retains two separate data sets: one that keeps the
data of all publication points as it was received from their remote repository,
and another – which we call the *store* – keeps the most recent data of a given
RPKI publication point that was found to be correctly published. 

Data is only transferred into the store if a manifest was found to be valid and
if all files mentioned on the manifest are present and have the correct hash.
Otherwise the data for the publication point already present in the store will
be used for validation.

If you ever want or need to clear the store, you use can the :option:`--fresh`
option. This will be like starting Routinator for the very first time.

.. code-block:: text

    routinator --fresh vrps