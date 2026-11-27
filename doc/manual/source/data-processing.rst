Data Processing
===============

Fetching
--------

There are two protocols in use to transport RPKI data: rsync and the :term:`RPKI
Repository Delta Protocol (RRDP)`, which relies on HTTPS. RRDP was designed to
be the successor to rsync in the RPKI. As all RPKI repositories currently
advertise support for both protocols, Routinator will prefer RRDP if 
available. 

In the RPKI, the certificate hierarchy follows the same structure as the
Internet number resource allocation hierarchy. Routinator starts traversing the
tree by connecting to the :term:`trust anchors <Trust Anchor (TA)>` of the
Regional Internet Registries (RIRs). Along the way Routinator will find several
pointers to child :term:`publication points <Publication Point>`, such as the
ones operated by National Internet Registries (NIRs), Local Internet Registries
(LIRs) and organisations running delegated RPKI. Each pointer explicitly states
if RRDP is offered in addition to rsync.

.. figure:: img/ca-structure.svg
    :align: center
    :width: 100%
    :alt: The RPKI hierarchy

    The RPKI hierarchy

As a precaution, Routinator will not accept rsync and HTTPS URIs from
:term:`RPKI repositories <Repository>` with dubious hostnames. In particular, it
will reject the name *localhost*, URIs that consist of IP addresses, and
hostnames that contain an explicit port. You can change this behaviour with the
:option:`--allow-dubious-hosts` option.

RRDP URLs and Redirects
"""""""""""""""""""""""

Routinator uses the notification URL in the CA certificate to determine
which HTTPS origin it will contact for that repository. This prevents a
notification file or an HTTP redirect from directing the validator to another
server to retrieve RRDP data.

Routinator checks that the snapshot and delta URLs in the notification use
the same hostname and port as the notification URL. The paths can differ.
An explicitly specified port must match in both URLs. For HTTP redirects,
Routinator checks that the scheme, host and port remain the same.

For example, if ``https://rpki.example.net/notification.xml`` lists a snapshot
at ``https://cdn.example.net/snapshot.xml``, Routinator rejects the
notification and logs ``snapshot or delta files with different origin``.

.. versionchanged:: 0.14.0
   RRDP retrieval is restricted to the origin of the notification URL.

RRDP Fallback
"""""""""""""

If an RRDP endpoint is unavailable but it has worked in the past, Routinator
will assume this is a transient problem. What action is taken is determined
by the :option:`--rrdp-fallback` option. The default policy is *stale*. This
means Routinator will retry using RRDP for up to 60 minutes since the last
successful update, during which it will rely on the locally cached data for
this repository. After this time, Routinator will try to use rsync to fetch
the data instead. To spread out load on the rsync server, the exact moment
fallback happens is picked randomly between the refresh time and the
:option:`--rrdp-fallback-time` value. If rsync communication is unsuccessful
too, the local cache is used until the objects go stale and ultimately
expire. 

Another policy for :option:`--rrdp-fallback` is *never*. This means that
rsync is never tried for a CA that advertises the availability of RRDP.
Lastly, the policy *new* means that rsync is tried if an update via RRDP
fails and there is no local copy of the RRDP repository at all. In other
words, an update via RRDP has never succeeded for the repository. Choosing
this policy allows a repository operator some leeway when first enabling RRDP
support.

.. versionadded:: 0.9.0

.. versionchanged:: 0.12.0
   The :option:`--rrdp-fallback` option

Update Interval
"""""""""""""""

Routinator will fetch new RPKI data ten minutes after the last successful update
has finished. The interval can be changed using the :option:`--refresh` option.
By default, Routinator allows 300 seconds for an rsync process to complete
(:option:`--rsync-timeout`) and 600 seconds for an HTTP request to retrieve
an RRDP resource (:option:`--rrdp-timeout`). Within an RRDP request,
:option:`--rrdp-read-timeout` limits how long Routinator waits for more data
on an individual read. The default read timeout is 10 seconds.

Validating
----------

Routinator also validates :doc:`ASPA objects <aspa>` and makes their payloads
available to compatible consumers. ASPA processing is enabled by default from
version 0.16.0.

The validation process determines if all certificates, Route Origin Authorisations
(ROAs) and other signed objects that may appear in the RPKI have the correct
signatures. It will also verify if the hashes are correct, no objects have
expired and the entire data set is complete. If any of the objects do not pass
these checks, the data will be discarded.

During repository validation, Routinator processes certificates (``.cer``),
certificate revocation lists (``.crl``), manifests (``.mft``), ROAs
(``.roa``), ASPAs (``.asa``) and Ghostbuster Records (``.gbr``).
If another type of object is encountered Routinator will *warn*
by default, but this can be changed with the :option:`--unknown-objects` option. 

Note that even if unknown objects are accepted, they must appear in the manifest
and the hash over their content must match the one given in the manifest. If the
hash does not match, the Certificate Authority (CA) and all its objects are
still rejected.

Manifest Updates
""""""""""""""""

Before replacing a stored publication point, Routinator checks that the new
manifest for that CA has both a higher manifest number and a later
``thisUpdate`` time than the stored manifest. If either value stays the same
or goes backwards on a changed manifest, Routinator logs a repository warning
and validates the stored publication point again. The usual validity and
staleness checks still apply to the stored data.

For example, after a repository is restored from backup, downloads may succeed
while Routinator continues to use the stored publication point. The warning
identifies the manifest and indicates which value failed the check.

.. versionchanged:: 0.14.0
   Routinator checks the manifest number and ``thisUpdate`` before accepting
   a replacement manifest.

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

ROAs and VRPs
"""""""""""""

ROAs are *cryptographic* objects that contain a statement authorising a *single*
Autonomous System Number (ASN) to originate *one or more* IP prefixes, along
with their maximum prefix length. ROAs can only be created by the legitimate
holder of the IP prefixes contained within it, but they can authorise any ASN.

If the ROA passes validation, Routinator will produce one or more *plain text*
validated ROA payloads (VRPs) for each ROA, depending on how many IP prefixes
are contained within it. Each VRP is a tuple of an ASN, a single prefix and its
maximum prefix length. The complete collection of VRPs can be expressed in
formats such as CSV or JSON, or exposed via the RPKI-to-Router (RTR) protocol so
that they can be compared to all BGP origins seen by your routers. For each
route origin it can be determined if they are RPKI *"Valid"*, *"Invalid"* or
*"NotFound"*.

Unsafe VRPs
"""""""""""

If the address prefix of a VRP overlaps with any resources assigned to a CA that
has been rejected because it failed to validate completely, the VRP is said to
be *unsafe* since using it may lead to legitimate routes being flagged as RPKI
Invalid.

The default :option:`--unsafe-vrps` policy, ``accept``, keeps these VRPs
without logging or counting them as unsafe. Use ``warn`` to monitor them or
``reject`` to exclude them from the dataset.

You can learn more about this topic in the :doc:`unsafe-vrps` section.

Storing
-------

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

.. versionadded:: 0.9.0
