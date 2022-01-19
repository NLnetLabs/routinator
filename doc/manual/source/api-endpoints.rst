API Endpoints
=============

.. versionchanged:: 0.9
   The ``/api/v1/status`` path
.. versionadded:: 0.9
   The ``/json-delta`` path

The service supports GET requests with the following paths:

``/api/v1/status``
     Returns exhaustive information in JSON format on all trust anchors,
     repositories, RRDP and rsync connections, as well as RTR and HTTP sessions.
     This data set provides the source for the Routinator user interface.

``/api/v1/validity/as-number/prefix``
     Returns a JSON object describing whether the route announcement given by 
     its origin AS Number and address prefix is RPKI valid, invalid, or not 
     found. A complete list of VRPs that caused the result is included.
     
``/validity?asn=as-number&prefix=prefix``
     Same as above but with a more form-friendly calling convention.
     
``/json-delta, /json-delta?sessionsession?serial=serial``
     Returns a JSON object with the changes since the dataset version identified
     by the *session* and *serial* query parameters. If a delta cannot be
     produced from that version, the full data set is returned and the member
     *reset* in the object will be set to *true*. In either case, the members
     *session* and *serial* identify the version of the data set returned and
     their values should be passed as the query parameters in a future request.

     The members *announced* and *withdrawn* contain arrays with route origins
     that have been announced and withdrawn, respectively, since the provided
     session and serial. If *reset* is *true*, the *withdrawn* member is not
     present.

In addition, the ``/log`` endpoint returns :doc:`logging<logging>`
information and the ``/metrics``, ``/status`` and
``/version`` endpoints provide :doc:`monitoring<monitoring>` data.
