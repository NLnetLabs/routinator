.. _doc_routinator_metrics_json:

JSON Metrics
============

Routinator's :ref:`monitoring service <doc_routinator_monitoring>` provides
comprehensive metrics in JSON format :command:`/api/v1/status` endpoint. Here
you can find an overview of all metrics and their meaning.

The JSON metrics consist of an object with the following members:

``version``
    The version of Routinator.
    
``serial``
    The current serial number for data served to
    :term:`RTR <RPKI-to-Router (RPKI-RTR)>` clients.
    
``now``
    The date and time in UTC when this report was created.
    
``lastUpdateStart``
    The date and time in UTC when the last validation run started.
    
``lastUpdateDone``
    The date and time in UTC when the last validation run completed.
    
``lastUpdateDuration``
    The duration of the last validation run in seconds.
    
``tals``
    Metrics for each configured trust anchor. In most cases these will be the
    five Regional Internet Registries, but will include the trust anchors of
    any configured :ref:`testbeds <doc_routinator_testbed>` as well.

    Each element of this object contains a
    :ref:`publication metrics value <doc_routinator_metrics_json_publication>`
    as described below.

``repositories``
    Metrics for each repository encountered during validation. Note that the
    data given here relates to the repository content used during validation.
    If the repository failed to update, then these numbers are from the stored
    old data.

    Each element of this object contains a
    :ref:`publication metrics value <doc_routinator_metrics_json_publication>`
    as described below. In addition, there is a member ``type`` that
    describes whether the repository is an RRDP or rsync repository.

``vrpsAddedLocally``
    The number of :term:`VRPs <Validated ROA Payload (VRP)>` added to the
    final data set from :ref:`local exceptions
    <doc_routinator_local_exceptions>`.

``rsync``
    Metrics for updates via rsync.

    This is an object with one element for each repository that was
    updated via rsync during the last validation run. Each element contains
    an :ref:`rsync update metrics value <doc_routinator_metrics_json_rsync>`
    as described below.

``rrdp``
    Metrics for updates via RRDP.

    This is an object with one element for each repository that was
    updated via rsync during the last validation run. Each element contains
    an :ref:`RRDP update metrics value <doc_routinator_metrics_json_rrdp>`
    as described below.

``rtr``
    Metrics for the built-in RTR server. See
    :ref:`RTR metrics <doc_routinator_metrics_json_rtr>` below.

``http``
    Metrics for the built-in HTTP server. See
    :ref:`HTTP metrics <doc_routinator_metrics_json_http>` below.


.. _doc_routinator_metrics_json_publication:

Publication Metrics
"""""""""""""""""""

Publication metrics are provided both for all trust anchors and for each
RPKI repository. They contain the following information:

``vrpsTotal``
    The total number of :term:`VRPs <Validated ROA Payload (VRP)>` found to be
    present and valid.

``vrpsUnsafe``
    The number of :term:`VRPs <Validated ROA Payload (VRP)>` that are considered
    :term:`unsafe <Unsafe VRPs>`. Depending on configuration, these may be
    included in the final set or dropped from it.

``vrpsLocallyFiltered``
    The number of :term:`VRPs <Validated ROA Payload (VRP)>` that are filtered
    as the result of a :ref:`local exception
    <doc_routinator_local_exceptions>`.

``vrpsDuplicate``
    The number of duplicate :term:`VRPs <Validated ROA Payload (VRP)>`
    resulting from ROAs containing the same authorisation.

    Note that if a VRP appears in multiple trust anchors or repositories,
    which occurrence is considered the duplicate depends on the order of
    processing which may change between validation runs. Thus, this number
    may change unexpectedly.

``vrpsFinal``
    The number of :term:`VRPs <Validated ROA Payload (VRP)>` that are
    contributed by this trust anchor or repository to the final set provided
    to your routers. This is the total number of VRPs,
    minus the ones that are locally filtered duplicate and, if configured
    to be dropped, unsafe.

``validPublicationPoints``
    The number of valid :term:`publication points <Publication Point>`.

``rejectedPublicationPoints``
    The number of rejected :term:`publication points <Publication Point>`.

    A publication point is rejected if its manifest is invalid or if any
    objects listed on the manifest are missing or have a different content
    hash.

``validManifests``
    The number of valid :term:`manifests <Manifest>`.

``invalidManifests``
    The number of invalid :term:`manifests <Manifest>`.

    A manifest is invalid if it is not correctly encoded, has expired or
    is not correctly signed by the issuing CA.

``staleManifests``
    The number of :term:`stale <Stale Object>` :term:`manifests <Manifest>`.

    A manifest is stale if the current time is past the time an update to
    the manifest should have been issued. Whether a stale manifest is valid
    or invalid depends on configuration. By default it is considered invalid.

``missingManifests``
    The number of missing :term:`manifests <Manifest>`.

``validCRLs``
    The number of valid :term:`certificate revocation lists <Certificate 
    Revocation List (CRL)>`.

``invalidCRLs``
    The number of invalid :term:`certificate revocation lists <Certificate 
    Revocation List (CRL)>`.

    A CRL is invalid if it is not correctly encoded or
    is not correctly signed by the issuing CA.

``staleCRLs``
    The number of :term:`stale <Stale Object>` :term:`certificate revocation
    lists <Certificate  Revocation List (CRL)>`.

    A CRL is stale if the current time is past the time an update
    should have been issued. Whether a stale CRL is valid
    or invalid depends on configuration. By default it is considered invalid.

``strayCRLs``
    The number of stray :term:`certificate revocation lists <Certificate 
    Revocation List (CRL)>`.

    Each CA should only issue one CRL. This CRL should both be listed on the
    manifest and used by the manifest’s certificate itself. Any manifest
    listed on the manifest that is not also the manifest’s own CRL is
    considered a stray.

``validCACerts``
    The number of Certificate Authority (CA) certificates found to be present
    and valid.

``validEECerts``
    The number of End Entity (EE) certificates found to be present and valid.

    This only refers to such certificates included as stand-alone files
    which are BGPsec router certificates.

``invalidCerts``
    The number of invalid stand-alone certificates, either CA or EE
    certificates.

``validROAs``
    The number of valid :term:`Route Origin Attestations <Route Origin 
    Attestation (ROA)>`

``invalidROAs``
    The number of invalid :term:`Route Origin Attestations <Route Origin 
    Attestation (ROA)>`.

``validGBRs``
    The number of valid :term:`Ghostbusters Records <Ghostbusters Record
    (GBR)>`.

    Note that currently the content of a Ghostbuster Record is not checked.

``InvalidGBRs``
    The number of invalid :term:`Ghostbusters Records 
    <Ghostbusters Record (GBR)>`.

``otherObjects``
    The number of objects found that are not certificates (.cer), Certificate 
    Revocation Lists (.crl), manifests (.mft), ROAs (.roa), or Ghostbuster 
    Records (.gbr).


.. _doc_routinator_metrics_json_rsync:

Rsync Update Metrics
""""""""""""""""""""

For each repository updated via rsync the following values are given.

``status``
    The status code returned by the rsync process. A value of 0 means the
    process has finished successfully. The meaning of other values depends
    on the rsync client used. Please refer to its documentation for further
    details.

``duration``
    The duration the rsync process was running in seconds.


.. _doc_routinator_metrics_json_rrdp:

RRDP Update Metrics
"""""""""""""""""""

For each repository updated via RRDP the following values are given.

``status``
    The overall status of the update. This will be 200 if the updated
    succeeded, 304 if no update was necessary because the data was already
    current, and any other value for a failed update with a value of -1
    indicating that it was even impossible to even reach the HTTPS server.

``notifyStatus``
    The status of retrieving the notification file. This is the first step
    of an RRDP update. A value of 200 indicates that the file was successfully
    retrieved. A value of 304 indicates that the file hasn’t changed since
    last update and no actual update is necessary. Any other value represents
    an error.

``payloadStatus``
    The status of retrieving the actual payload. This is the second step
    of an RRDP update and may either represent a single HTTPS request for
    the snapshot file or a series of HTTPS request for the sequence of delta
    files necessary to update from the last known state.

    A value of 0 means that no payload retrieval was necessary. A value of
    200 means that the update was successful. Any other value indicates an
    error. In case of a sequence of delta updates, this error may have been
    preceded by one or more successful requests.

``duration``
    The overall duration of the RRDP update in seconds.

``serial``
    The serial number stated by the RRDP server for the current data set.
    With each update the serial number is increased by one.

``session``
    The identifier of the current session of the RRDP server. Serial numbers
    are only valid within the same session. If the server needs to restart its
    sequence for whatever reason, it needs to choose a new session ID and all
    data will have to be updated through a snapshot.

``delta``
    Whether data was updated via a sequence of deltas (``true``) or a full
    snapshot had to be retrieved (``false``).

``snapshotReason``
    If this is not ``null``, it provides a reason why a snapshot was used
    instead of a delta as a short explanatory string.


.. _doc_routinator_metrics_json_rtr:

RTR Server Metrics
""""""""""""""""""

A number of metrics are provided describing the state of the included RTR
server. These metrics are available whether the RTR server is actually
enabled or not.

``currentConnections``
   The number of currently open RTR connections.

``bytesRead``
   The total number of bytes read from RTR connections. In other words,
   describes how much data has been sent by clients.

``bytesWritten``
   The total number of bytes written to RTR connections. In other words,
   describes how much data has been sent to clients.

If ``rtr-client-metrics`` are enabled via configuration or command line,
an additional object ``clients`` will appear that list the IP addresses of
clients seen by the RTR server providing the following information for them.

``connections``
   The number of currently open connections from that address. The number
   should normally be 0 or 1 but can be higher if the address is the public
   side of a NAT.

``serial``
   The highest serial of the data provided to a client from that address.
   This can be used to determine when the client has last updated.

``read`` and ``written``
   Bytes read from and written to clients from that address.


.. _doc_routinator_metrics_json_http:

HTTP Server Metrics
"""""""""""""""""""

A number of metrics are provided describing the state of the included HTTP
server.

``totalConnections``
   The total number of connections made with the HTTP server.

``currentConnections``
   The number of currently open connections. This should at least be 1 as
   there is a connection open when requesting the JSON metrics.

``requests``
   The total number of requests received and answered by the HTTP server.

``bytesRead`` and ``bytesWritten``
   The number of bytes read from and written to HTTP clients.
