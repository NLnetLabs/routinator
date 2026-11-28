JSON Metrics
============

The :doc:`monitoring service <monitoring>` returns a JSON object at
``/api/v1/status``. Until the first validation metrics are available, the
endpoint returns HTTP 503. A successful response has the following members:

``version``
    The version of Routinator.
    
``serial``
    The current :term:`serial number <RTR session ID and serial number>` for data served to
    :term:`RTR <RPKI-to-Router (RPKI-RTR)>` clients.
    
``now``
    The date and time in UTC when this report was created.
    
``lastUpdateStart``
    The date and time in UTC when the last validation run started.
    
``lastUpdateDone``
    The date and time in UTC when the last validation run completed, or ``null``
    if no completion time is available.
    
``lastUpdateDuration``
    The duration of the last completed validation run in seconds, or ``null``
    if unavailable.
    
``payload``
    Counts for the whole validation run, grouped by payload type. See
    :ref:`json-metrics:payload metrics` for the fields and their scope.

``aspasLargeProviderSet``
    Number of customer ASNs omitted from the snapshot because their combined
    provider set exceeded the size limit. See :doc:`aspa`.

``tals``
    Metrics for each configured :term:`trust anchor <Trust Anchor (TA)>`. In
    most cases these will be the five :term:`Regional Internet Registries
    <Regional Internet Registry (RIR)>`, but will include the trust anchors of
    any configured :ref:`testbeds <configuration:trust anchor locators>` as
    well.

    Each element of this object contains a :ref:`publication metrics value
    <json-metrics:publication metrics>` as described below.

``repositories``
    Metrics for each :term:`repository` encountered during validation. Note that the
    data given here relates to the repository content used during validation.
    If the repository failed to update, then these numbers are from the stored
    old data.

    Each element of this object contains a :ref:`publication metrics value
    <json-metrics:publication metrics>` as described below. In addition, there
    is a member ``type`` that describes whether the repository is an :term:`RRDP
    <RPKI Repository Delta Protocol (RRDP)>` or
    rsync repository. Its possible values are ``"RRDP"``, ``"rsync"`` and
    ``"other"``.

``vrpsAddedLocally``
    The number of :term:`VRPs <Validated ROA Payload (VRP)>` added to the final
    data set from :doc:`local exceptions<local-exceptions>`.

``rsync``
    Metrics for updates via rsync.

    This is an object with one element for each repository that was updated via
    rsync during the last validation run. Each element contains an :ref:`rsync
    update metrics value <json-metrics:rsync update metrics>` as described
    below.

``rrdp``
    Metrics for updates via RRDP.

    This is an object with one element for each repository that was updated via
    RRDP during the last validation run. Each element contains an :ref:`RRDP
    update metrics value <json-metrics:rrdp update metrics>` as described below.

``pubPointIssues``
    An object keyed by publication point URI. Each value is an array of
    :ref:`log entries <json-metrics:issue entries>`. The object can be empty.

``rtr``
    Metrics for the built-in RTR server. See
    :ref:`RTR metrics <json-metrics:rtr server metrics>` below.

``http``
    Metrics for the built-in HTTP server. See
    :ref:`HTTP metrics <json-metrics:http server metrics>` below.

Payload Metrics
"""""""""""""""

The top-level ``payload`` object covers the whole run. Each entry in ``tals``
and ``repositories`` also has a ``payload`` object for that source. All three
use the same four groups: ``routeOriginsIPv4``, ``routeOriginsIPv6``,
``routerKeys`` and ``aspas``. Each group reports:

* ``total``: valid published payloads processed, before local filters.
* ``locallyFiltered``: payloads removed by local exceptions.
* ``duplicate``: additional contributions counted against an existing entry.
  For ASPA, entries are grouped by customer ASN. A second provider list can
  contribute new providers to an existing entry.
* ``final``: entries contributed after filtering and combining duplicates.
  The top-level count includes new entries from local assertions.
* ``unsafe`` (IPv4 and IPv6 route origins only): VRPs marked unsafe under
  the configured policy.

For ASPA, ``payload.aspas.final`` counts customer entries before the
provider-set size limit is applied. Subtract ``aspasLargeProviderSet`` from
the top-level count to obtain the number of customer entries in the snapshot.
The separate ``validASPAs`` and ``invalidASPAs`` fields count signed objects
at each trust anchor or repository.

Publication Metrics
"""""""""""""""""""

Publication metrics are provided both for all trust anchors
and for each
:term:`RPKI <Resource Public Key Infrastructure (RPKI)>` repository. They contain
the following information:

``vrpsTotal``
    The total number of VRPs found to be
    present and valid.

``vrpsUnsafe``
    The number of VRPs that are considered
    :term:`unsafe <Unsafe VRPs>`. Depending on configuration, these may be
    included in the final set or dropped from it.

``vrpsLocallyFiltered``
    The number of VRPs that are filtered
    as the result of a :doc:`local exception<local-exceptions>`.

``vrpsDuplicate``
    The number of duplicate VRPs
    resulting from :term:`ROAs <Route Origin Authorisation (ROA)>` containing the same
    authorisation.

    Note that if a VRP appears in multiple
    trust anchors or repositories,
    which occurrence is considered the duplicate depends on the order of
    processing which may change between validation runs. Thus, this number
    may change unexpectedly.

``vrpsFinal``
    The number of VRPs that are
    contributed by this trust anchor or repository to
    the final set provided
    to your routers. This is the total number of VRPs,
    minus the ones that are locally filtered, duplicate, and, if configured to 
    be dropped, unsafe.

``validPublicationPoints``
    The number of valid :term:`publication points <Publication Point>`.

``rejectedPublicationPoints``
    The number of rejected publication points.

    A publication point is rejected if its :term:`manifest` is invalid or if any
    objects listed on the manifest are missing or have a different content
    hash.

``validManifests``
    The number of valid manifests.

``invalidManifests``
    The number of invalid manifests.

    A manifest is invalid if it is not correctly encoded, has expired or
    is not correctly signed by the issuing :term:`CA <Certification authority (CA)>`.

``prematureManifests``
    The number of manifests whose ``thisUpdate`` time is in the future.

``staleManifests``
    The number of :term:`stale <Stale Object>` manifests.

    A manifest is stale if the current time is past the time an update to
    the manifest should have been issued. Whether a stale manifest is valid
    or invalid depends on configuration. By default it is considered invalid.

``missingManifests``
    The number of missing manifests.

``validCRLs``
    The number of valid :term:`certificate revocation lists <Certificate 
    Revocation List (CRL)>`.

``invalidCRLs``
    The number of invalid certificate revocation lists.

    A CRL is invalid if it is not correctly
    encoded or
    is not correctly signed by the issuing CA.

``staleCRLs``
    The number of stale certificate revocation
    lists.

    A CRL is stale if the current time is past
    the time an update
    should have been issued. Whether a stale CRL is valid
    or invalid depends on configuration. By default it is considered invalid.

``strayCRLs``
    The number of stray certificate revocation lists.

    Each CA should only issue one CRL. This CRL should both be listed on the
    manifest and used by the manifest’s certificate itself. Any CRL
    listed on the manifest that is not also the manifest’s own CRL is
    considered a stray.

``validCACerts``
    The number of Certificate Authority (CA)
    certificates found to be present
    and valid.

``validRouterCerts``
    The number of valid stand-alone :term:`BGPsec router certificates
    <BGPsec router certificate>`.

``validEECerts``
    A deprecated name for the same count as ``validRouterCerts``.

``invalidCerts``
    The number of invalid stand-alone certificates, either CA or EE
    certificates.

``validROAs``
    The number of valid Route Origin Authorisations

``invalidROAs``
    The number of invalid Route Origin Authorisations.

``validASPAs``
    The number of valid :term:`ASPA <Autonomous System Provider Authorisation
    (ASPA)>` objects.

``invalidASPAs``
    The number of invalid ASPA objects.

``validGBRs``
    The number of valid :term:`Ghostbusters Records <Ghostbusters Record
    (GBR)>`.

    Note that currently the content of a Ghostbuster Record is not checked.

``invalidGBRs``
    The number of invalid Ghostbusters Records.

``otherObjects``
    The number of objects found that are not certificates (.cer), Certificate
    Revocation Lists (.crl), manifests (.mft), ROAs (.roa), ASPAs (.asa), or
    Ghostbusters Records (.gbr).

Rsync Update Metrics
""""""""""""""""""""

For each repository updated via rsync the following values are given.

``status``
    The status code returned by the rsync process. A value of 0 means the
    process has finished successfully. The meaning of other values depends
    on the rsync client used. Please refer to its documentation for further
    details.

``duration``
    The duration the rsync process was running in seconds, or ``null`` if
    unavailable.

``issues``
    An optional array of :ref:`log entries <json-metrics:issue entries>` for
    this rsync module.

RRDP Update Metrics
"""""""""""""""""""

For each repository updated via RRDP the following values are given.

``status``
    The overall status of the update. This will be 200 if the update
    succeeded, 304 if no update was necessary because the data was already
    current, and any other value for a failed update. If the value is -1,
    it was not possible to reach the HTTPS server at all.

``notifyStatus``
    The status of retrieving the :term:`notification file <RRDP notification file>`. This
    is the first step
    of an RRDP update. A value of 200
    indicates that the file was successfully
    retrieved. A value of 304 indicates that the file hasn’t changed since
    last update and no actual update is necessary. Any other value represents
    an error.

``payloadStatus``
    The status of retrieving the actual payload. This is the second step
    of an RRDP update and may either
    represent a single HTTPS request for
    the :term:`snapshot <RRDP snapshot>` file or a series of HTTPS request for the
    sequence of :term:`delta <RRDP delta>`
    files necessary to update from the last known state.

    A value of 0 means that no payload retrieval was necessary. A value of
    200 means that the update was successful. Any other value indicates an
    error. In case of a sequence of delta updates, this error may have been
    preceded by one or more successful requests.

``duration``
    The overall duration of the RRDP update in seconds, or ``null`` if
    unavailable.

``issues``
    An optional array of :ref:`log entries <json-metrics:issue entries>` for
    this notification URI.

When ``status`` is 304, the following four members are omitted.

``serial``
    The :term:`serial number <RRDP session ID and serial number>` stated by the
    RRDP server for the current data set, or ``null`` if unavailable.
    With each update the serial number is
    increased by one.

``session``
    The identifier of the current session of the RRDP server, or ``null`` if
    unavailable. Serial numbers
    are only valid within the same session. If the server needs to restart its
    sequence for whatever reason, it needs to choose a new session ID and all
    data will have to be updated through a snapshot.

``delta``
    ``false`` when a snapshot reason was recorded and ``true`` otherwise.
    Use ``status`` to determine whether the update succeeded.

``snapshot_reason``
    If this is not ``null``, it provides a reason why a snapshot
    was used
    instead of a delta as a short explanatory string.

Issue Entries
"""""""""""""

Each entry in ``pubPointIssues`` or a transport's ``issues`` array contains
three strings: ``level`` is the severity for the application log,
``repository_level`` is the severity for the repository log and
``message`` is the log text.

RTR Server Metrics
""""""""""""""""""

A number of metrics are provided describing the state of the included RTR
server. These metrics are available whether the RTR
server is actually
enabled or not.

``currentConnections``
   The number of currently open RTR connections.

``bytesRead``
   The total number of bytes read from RTR
   connections. In other words,
   describes how much data has been sent by clients.

``bytesWritten``
   The total number of bytes written to RTR
   connections. In other words,
   describes how much data has been sent to clients.

If ``rtr-client-metrics`` are enabled via configuration or command line,
an additional object ``clients`` will appear that list the IP addresses of
clients seen by the RTR server providing the following
information for them. The ``serial``, ``updated`` and ``lastReset`` fields are
``null`` until the corresponding values are available.

``connections``
   The number of currently open connections from that address. The number
   should normally be 0 or 1 but can be higher if the address is the public
   side of a NAT.

``updated`` 
   Contains the time of the last successful update by the client.

``lastReset`` 
   Contains the time of the last successful cache reset by the client.

``resetQueries`` 
   Contains the number of reset queries by the client.

``serialQueries`` 
   Contains the number of serial queries by the client.

``serial``
   The highest serial of the data provided to a client from that address.
   This can be used to determine when the client has last updated.

``read`` and ``written``
   Bytes read from and written to clients from that address.

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
