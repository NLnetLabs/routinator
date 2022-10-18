Prometheus Metrics
==================

Routinator's :doc:`monitoring service<monitoring>` provides comprehensive
metrics in Prometheus format at the ``/metrics`` endpoint. Here you can
find an overview of all metrics and their meaning.

``routinator_last_update_start``
    Seconds since the start of the last update.
    
``routinator_last_update_duration``
    Duration of the last update in seconds.

``routinator_last_update_done``
    Seconds since the end of the last update.

``routinator_serial``
    The current serial number for data served to
    :term:`RTR <RPKI-to-Router (RPKI-RTR)>` clients.

Publication Metrics
"""""""""""""""""""

Publication metrics are provided for all trust anchors and for each RPKI
repository. 

All metrics for trust anchors have a label ``name``, named after the Trust
Anchor Locator file name without the *.tal* extension, e.g. *arin*. All metrics
for repositories have a label ``uri`` specifying the URI of the notification
file of the RRDP repository, or the base URI of the rsync repository.

``routinator_{ta,repository}_publication_points_total``
    The number of :term:`publication points <Publication Point>` per trust
    anchor. In most cases these will be the five Regional Internet Registries,
    but will include the trust anchors of any configured :ref:`testbeds
    <initialisation:preparing for test environments>` as well. 
    
    This metric has two labels: either ``name`` or ``uri``, followed by the
    ``state`` which is *valid* or *rejected*.

``routinator_{ta,repository}_objects_total``
    Metrics for each configured trust anchor. In most cases these will be the
    five Regional Internet Registries, but will include the trust anchors of any
    configured :ref:`testbeds <initialisation:preparing for test environments>`
    as well. 
    
    This metric has three labels: either ``name`` or ``uri``, followed by
    ``type`` for the type of object, e.g. *crl*, and lastly ``state`` describing
    its validity state, such as *valid* or *stale*.
    
    The types and states of objects can be:
      * ``manifest`` - The number of :term:`manifests <Manifest>` for each of 
        the states *valid*, *invalid*, *stale* and *missing*. A manifest is
        *invalid* if it is not correctly encoded, has expired or is not
        correctly signed by the issuing CA. It is considered *stale* if the
        current time is past the time an update to the manifest should have been
        issued. Whether a *stale* manifest is *valid* or *invalid* depends on
        configuration. By default a *stale* manifest is considered *invalid*.
      * ``crl`` - The number of :term:`certificate revocation lists <Certificate 
        Revocation List (CRL)>` for each of the states *valid*, *invalid*,
        *stale* and *stray*. A CRL is *invalid* if it is not correctly encoded
        or is not correctly signed by the issuing CA. It is considered *stale*
        if the current time is past the time an update to the manifest should
        have been issued. Whether a *stale* manifest is *valid* or *invalid*
        depends on configuration. By default a *stale* CRL is considered
        *invalid*. Lastly, each CA should only issue one CRL. This CRL should
        both be listed on the manifest and used by the manifest’s certificate
        itself. Any manifest listed on the manifest that is not also the
        manifest’s own CRL is considered a *stray*.
      * ``ca_cert`` - The number of Certificate Authority (CA) certificates with 
        the state *valid*.
      * ``router_cert`` - The number of End Entity (EE) certificates found to be
        present and *valid*. This only refers to such certificates included as 
        stand-alone files which are BGPsec router certificates.
      * ``roa`` - The number of :term:`Route Origin Attestations <Route Origin 
        Attestation (ROA)>` for each of the states *valid* and *invalid*.
      * ``gbr`` - The number of :term:`Ghostbusters Records <Ghostbusters Record
        (GBR)>` for each of the states *valid* and *invalid*. Note that
        currently the content of a Ghostbuster Record is not checked.
      * ``other`` - The number of objects found that are not certificates 
        (.cer), Certificate  Revocation Lists (.crl), manifests (.mft), ROAs
        (.roa), or Ghostbuster  Records (.gbr) and have the state *invalid*.

The following metrics all have just one label, either ``name`` in case of a 
trust anchor or ``uri`` for repositories:

``routinator_{ta,repository}_valid_vrps_total``
    The number of :term:`VRPs <Validated ROA Payload (VRP)>` found to be
    present and valid. 
    
``routinator_{ta,repository}_unsafe_vrps_total``
    The number of :term:`VRPs <Validated ROA Payload (VRP)>` found to be
    :term:`unsafe <Unsafe VRPs>`. 
    
``routinator_{ta,repository}_locally_filtered_vrps_total``
    The number of :term:`VRPs <Validated ROA Payload (VRP)>` that are filtered
    as the result of a :doc:`local exception <local-exceptions>`.

``routinator_{ta,repository}_duplicate_vrps_total``
    The number of duplicate :term:`VRPs <Validated ROA Payload (VRP)>`
    resulting from ROAs containing the same authorisation. 

    Note that if a VRP appears in multiple trust anchors or repositories,
    which occurrence is considered the duplicate depends on the order of
    processing which may change between validation runs. Thus, this number
    may change unexpectedly.

``routinator_{ta,repository}_contributed_vrps_total``
    The number of :term:`VRPs <Validated ROA Payload (VRP)>` that are
    contributed by this trust anchor or repository to the final set provided to
    your routers. This is the total number of VRPs, minus the ones that are
    locally filtered, duplicate, and, if configured to be dropped, unsafe.

Rsync Update Metrics
""""""""""""""""""""

For each repository updated via rsync the following values are given.

``routinator_rsync_status``
    The status code returned by the rsync process. A value of 0 means the
    process has finished successfully. The meaning of other values depends
    on the rsync client used. Please refer to its documentation for further
    details.

``routinator_rsync_duration``
    The duration the rsync process was running in seconds.

RRDP Update Metrics
"""""""""""""""""""

For each repository updated via RRDP the following values are given. All metrics 
have a label ``uri`` specifying the URI of the notification file of the RRDP 
repository.

``routinator_rrdp_status``
    The overall status of the update. This will be 200 if the updated
    succeeded, 304 if no update was necessary because the data was already
    current, and any other value for a failed update. If the value is -1,
    it was not possible to reach the HTTPS server at all.

``routinator_rrdp_notification_status``
    The status of retrieving the notification file. This is the first step
    of an RRDP update. A value of 200 indicates that the file was successfully
    retrieved. A value of 304 indicates that the file hasn’t changed since
    last update and no actual update is necessary. Any other value represents
    an error.

``routinator_rrdp_payload_status``
    The status of retrieving the actual payload. This is the second step
    of an RRDP update and may either represent a single HTTPS request for
    the snapshot file or a series of HTTPS request for the sequence of delta
    files necessary to update from the last known state.

    A value of 0 means that no payload retrieval was necessary. A value of
    200 means that the update was successful. Any other value indicates an
    error. In case of a sequence of delta updates, this error may have been
    preceded by one or more successful requests.

``routinator_rrdp_duration``
    The overall duration of the RRDP update in seconds.

``routinator_rrdp_serial_info``
    The serial number stated by the RRDP server for the current data set.
    With each update the serial number is increased by one.

RTR Server Metrics
""""""""""""""""""

A number of metrics are provided describing the state of the included RTR
server. These metrics are available whether the RTR server is actually
enabled or not.

``routinator_rtr_current_connections``
   The number of currently open RTR connections.

``routinator_rtr_bytes_read``
   The total number of bytes read from RTR connections. In other words,
   describes how much data has been sent by clients.

``routinator_rtr_bytes_written``
   The total number of bytes written to RTR connections. In other words,
   describes how much data has been sent to clients.

``routinator_rtr_client_last_reset_seconds`` 
   The amount of seconds since last cache reset by a client address.

``routinator_rtr_client_reset_queries`` 
   The number of of reset queries by a client address.

``routinator_rtr_client_serial_queries`` 
   The number of of serial queries by a client address.

.. versionadded:: 0.12.0
   ``routinator_rtr_client_last_reset_seconds``, 
   ``routinator_rtr_client_reset_queries`` and
   ``routinator_rtr_client_serial_queries``

HTTP Server Metrics
"""""""""""""""""""

A number of metrics are provided describing the state of the included HTTP
server.

``routinator_http_connections``
   The total number of connections made with the HTTP server.

``routinator_http_current_connections``
   The number of currently open connections. This should at least be 1 as
   there is a connection open when requesting the JSON metrics.

``requests``
   The total number of requests received and answered by the HTTP server.

``routinator_http_bytes_read`` and ``routinator_http_bytes_written``
   The number of bytes read from and written to HTTP clients.
