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
is offered in addition to rsync. 

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

Validating
----------

The validation process determines if all certificates, Route Origin Attestations
(ROAs) and other signed objects that may appear in the RPKI have the correct
signatures. It will also verify if the hashes are correct, no objects have
expired and the entire data set is complete. If any of the objects do not pass
these checks, the data will be discarded.

ROAs are objects that contain a statement authorising a *single* Autonomous
System Number (ASN) to originate *one or more* IP prefixes, along with their
maximum prefix length. A ROA can only be created by the legitimate holder of the
IP prefixes contained within it, but it can authorise any ASN.

If the ROA passes validation, Routinator will produce one or more validated ROA
payloads (VRPs) for each ROA, depending on how many IP prefixes are contained
within it. Each VRP is a tuple of an ASN, a single prefix and its maximum
prefix length. 

Stale Objects
"""""""""""""

During the validation process, Routinator may encounter objects that are
*stale*. In RPKI, manifests and :abbr:`CRLs (Certificate Revocation Lists)` can
be stale if the time given in their ``next-update`` field is in the past,
indicating that an update to the object was scheduled but didn't happen. This
can be because of an operational issue at the issuer or an attacker trying to
replay old objects. 

Ongoing standards efforts and operational experiences suggest that stale objects
should be rejected, which is the default policy set by the :option:`--stale`
option since Routinator 0.8.0. As a result, all material published by the CA
issuing this manifest and CRL is considered invalid, including all material of
any child CA.

Unsafe VRPs
"""""""""""

If the address prefix of a VRP overlaps
with any resources assigned to a CA that has been rejected because if  failed  to  validate
completely, the VRP is said to be unsafe since using it may lead to legitimate routes being
flagged as RPKI invalid.

There are three options how to deal with unsafe VRPS:

A policy of reject will filter out these VPRs. Warnings will be logged  to  indicate  which
VRPs have been filtered

The warn policy will log warnings for unsafe VRPs but will add them to the valid VRPs.

Finally, the accept policy will quietly add unsafe VRPs to the valid VRPs.

Currently, the default policy is warn in order to gain operational experience with the fre-
quency and impact of unsafe VRPs. This default may change in future version.

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
