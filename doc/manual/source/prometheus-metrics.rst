Prometheus Metrics
==================

Routinator's :doc:`monitoring service<monitoring>` provides comprehensive
metrics in Prometheus format at the ``/metrics`` endpoint. Here you can
find an overview of all metrics and their meaning. Until validation metrics
are available, this endpoint returns HTTP 503.

Validation and repository metrics are gauges: they describe the latest run
and can decrease, including the families whose names end in ``_total``.
Server metrics that accumulate bytes, queries, requests or opened connections
are counters. Current connection counts, serial numbers and elapsed times
are gauges.

``routinator_last_update_start``
    Seconds since the start of the last update.
    
``routinator_last_update_duration``
    Duration of the last completed update in whole seconds, or ``NaN`` if unavailable.

``routinator_last_update_done``
    Seconds since the end of the last completed update, or ``NaN`` if unavailable.

``routinator_serial``
    The current :term:`serial number <RTR session ID and serial number>` for data served to
    :term:`RTR <RPKI-to-Router (RPKI-RTR)>` clients.

``routinator_vrps_added_locally``
    Number of VRPs contributed by locally added assertions.

``routinator_aspa_large_provider_set``
    Number of customer ASNs omitted from the snapshot because their
    combined ASPA provider set exceeded the size limit. See :doc:`aspa`.

Publication Metrics
"""""""""""""""""""

Publication metrics are provided for all :term:`trust anchors <Trust Anchor (TA)>` and for
each :term:`RPKI <Resource Public Key Infrastructure (RPKI)>`
:term:`repository`.

All metrics for trust anchors have a label ``name``, named
after the :term:`Trust
Anchor Locator <Trust Anchor Locator (TAL)>` file name without the *.tal* extension, e.g.
*arin*. All metrics
for repositories have a label ``uri`` specifying the URI of the
:term:`notification
file <RRDP notification file>` of the :term:`RRDP <RPKI Repository Delta Protocol (RRDP)>`
repository, or the base URI of the rsync repository.

``routinator_{ta,repository}_publication_points_total``
    Number of :term:`publication points <Publication Point>` for this trust
    anchor or repository, with ``state="valid"`` or ``state="rejected"``.

``routinator_{ta,repository}_objects_total``
    Number of objects for this trust anchor or repository, grouped by
    ``type`` and ``state``. The following combinations are exported:

    .. list-table::
       :header-rows: 1

       * - Object type
         - States
       * - ``manifest``
         - ``valid``, ``invalid``, ``premature``, ``stale``, ``missing``
       * - ``crl``
         - ``valid``, ``invalid``, ``stale``, ``stray``
       * - ``ca_cert``, ``router_cert``
         - ``valid``
       * - ``cert``
         - ``invalid``
       * - ``roa``, ``aspa``, ``gbr``
         - ``valid``, ``invalid``
       * - ``other``
         - ``invalid``

    A premature manifest has a ``thisUpdate`` time in the future. A stale
    manifest or CRL has passed its ``nextUpdate`` time. The stale policy
    determines whether Routinator accepts it. A stray CRL is listed on a
    manifest but is not the CRL used by the manifest's certificate.
    Invalid stand-alone certificates share the ``cert`` label. For
    Ghostbusters Records, Routinator checks the signed object and its
    certificate without parsing the vCard.

The following metrics all have just one label, either ``name`` in case of a 
trust anchor or ``uri`` for repositories:

``routinator_{ta,repository}_valid_vrps_total``
    The number of :term:`VRPs <Validated ROA Payload (VRP)>` found to be
    present and valid. 
    
``routinator_{ta,repository}_unsafe_vrps_total``
    The number of VRPs found to be
    :term:`unsafe <Unsafe VRPs>`. This series is emitted only when the
    unsafe VRP policy is ``warn`` or ``reject``.
    
``routinator_{ta,repository}_locally_filtered_vrps_total``
    The number of VRPs that are filtered
    as the result of a :doc:`local exception <local-exceptions>`.

``routinator_{ta,repository}_duplicate_vrps_total``
    The number of duplicate VRPs
    resulting from ROAs containing the same
    authorisation.

    Note that if a VRP appears in multiple
    trust anchors or repositories,
    which occurrence is considered the duplicate depends on the order of
    processing which may change between validation runs. Thus, this number
    may change unexpectedly.

``routinator_{ta,repository}_contributed_vrps_total``
    The number of VRPs that are
    contributed by this trust anchor or repository to
    the final set provided to
    your routers. This is the total number of VRPs,
    minus the ones that are
    locally filtered, duplicate, and, if configured to be dropped, unsafe.

Payload Metrics
"""""""""""""""

These gauges have a source label (``name`` for a trust anchor or ``uri``
for a repository) and a ``type`` label. For IPv4 VRPs, IPv6 VRPs and
BGPsec router keys, the type values are ``route_origins_ipv4``,
``route_origins_ipv6`` and ``router_keys``, respectively.

``routinator_{ta,repository}_valid_payload_total``
    Valid published payloads processed before local filtering.

``routinator_{ta,repository}_unsafe_payload_total``
    Payloads marked unsafe. Emitted for the ``warn`` and ``reject`` policies.
    The unsafe check applies to VRPs. The router key series is zero.

``routinator_{ta,repository}_locally_filtered_payload_total``
    Payloads removed by local exceptions.

``routinator_{ta,repository}_duplicate_payload_total``
    Additional contributions counted against an existing entry.

``routinator_{ta,repository}_contributed_payload_total``
    Entries contributed by the source after filtering and deduplication.

For :term:`ASPA <Autonomous System Provider Authorisation (ASPA)>` payloads,
``type="aspas"`` is exported only for the valid, duplicate and contributed
families. Routinator groups provider lists by customer ASN. An additional
list counted as a duplicate can still add providers to an existing entry.
Contributions are counted before the combined provider-set size check.
To count signed ASPA objects instead, use the object metric, for example
``routinator_ta_objects_total{type="aspa",state="valid"}``.

Rsync Update Metrics
""""""""""""""""""""

These metrics use the rsync module URI as the ``uri`` label.

``routinator_rsync_status``
    The status code returned by the rsync process. A value of 0 means the
    process has finished successfully. The meaning of other values depends
    on the rsync client used. Please refer to its documentation for further
    details. A value of -1 means no exit code was available.

``routinator_rsync_duration``
    The duration the rsync process was running in seconds, when available.

RRDP Update Metrics
"""""""""""""""""""

For each repository updated via RRDP the following values are given. All metrics
have a label ``uri`` specifying the URI of the notification file of the RRDP
repository.

``routinator_rrdp_status``
    The HTTP status of the notification request, or of the payload request
    when one followed a successful notification request. A 304 indicates an
    unchanged notification file. A value of -1 indicates a request error. A value of
    -2 indicates that Routinator rejected the repository before fetching.

``routinator_rrdp_notification_status``
    The status of retrieving the notification file. This
    is the first step
    of an RRDP update. A value of 200
    indicates that the file was successfully
    retrieved. A value of 304 indicates that the file hasn’t changed since
    last update and no actual update is necessary. Any other value represents
    an error.

``routinator_rrdp_payload_status``
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

``routinator_rrdp_duration``
    The overall duration of the RRDP update in seconds, when available.

``routinator_rrdp_serial_info``
    The :term:`serial number <RRDP session ID and serial number>` stated by the
    RRDP server for the current data set, when available.
    With each update the serial number is
    increased by one.

RTR Server Metrics
""""""""""""""""""

A number of metrics are provided describing the state of the included RTR
server. These metrics are available whether the RTR
server is actually
enabled or not.

``routinator_rtr_current_connections``
   The number of currently open RTR connections.

``routinator_rtr_bytes_read``
   The total number of bytes read from RTR
   connections. In other words,
   describes how much data has been sent by clients.

``routinator_rtr_bytes_written``
   The total number of bytes written to RTR
   connections. In other words,
   describes how much data has been sent to clients.

The following per-client metrics require :option:`--rtr-client-metrics`
and carry an ``addr`` label for the client IP address.

``routinator_rtr_client_connections``
   Currently open connections from this address.

``routinator_rtr_client_serial``
   The serial reported for this client address, or -1 if unavailable.

``routinator_rtr_client_last_update_seconds``
   Seconds since the client's last update, or -1 if unavailable.

``routinator_rtr_client_read_bytes`` and ``routinator_rtr_client_written_bytes``
   Bytes received from and sent to clients at this address, respectively.

``routinator_rtr_client_last_reset_seconds``
   Seconds since the last cache reset for this address, or -1 if unavailable.

``routinator_rtr_client_reset_queries`` 
   The number of reset queries by a client address.

``routinator_rtr_client_serial_queries`` 
   The number of serial queries by a client address.

HTTP Server Metrics
"""""""""""""""""""

A number of metrics are provided describing the state of the included HTTP
server.

``routinator_http_connections``
   The total number of connections made with the HTTP server.

``routinator_http_current_connections``
   The number of currently open connections. This should at least be 1 as
   there is a connection open when scraping this endpoint.

``routinator_http_requests``
   The total number of requests received and answered by the HTTP server.

``routinator_http_bytes_read`` and ``routinator_http_bytes_written``
   The number of bytes read from and written to HTTP clients.

Deprecated Metrics
""""""""""""""""""

The exporter also provides the following gauges for existing dashboards:

* ``routinator_valid_roas``, ``routinator_total_vrps``,
  ``routinator_vrps_unsafe``, ``routinator_vrps_filtered_locally`` and
  ``routinator_vrps_duplicate`` report valid ROAs, valid VRPs, unsafe VRPs,
  locally filtered VRPs and duplicate VRPs, respectively. They use the
  label ``tal``. Unsafe samples require the ``warn`` or ``reject`` policy.
* ``routinator_vrps_final`` is the number of VRPs in the final data set.
* ``routinator_stale_objects`` is the combined count of stale manifests
  and CRLs.
