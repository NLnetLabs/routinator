API Endpoints
=============

The HTTP service supports **GET** requests on the following paths:

``/api/v1/status``
     Returns exhaustive information in JSON format on all trust anchors,
     repositories, RRDP and rsync connections, as well as RTR and HTTP
     sessions. This data set provides the source for the Routinator user
     interface.

``/api/v1/validity/as-number/prefix``
     Returns a JSON object describing whether the route announcement given by
     its origin AS Number and address prefix is RPKI valid, invalid, or not
     found. A complete list of VRPs that caused the result is included. For
     details about its contents see :doc:`validity checker<validity-checker>`.
     
``/validity?asn=as-number&prefix=prefix``
     Same as above but with a more form-friendly calling convention.
     
``/json-delta, /json-delta?session=session?serial=serial``
     Returns a JSON object with the changes since the dataset version
     identified by the *session* and *serial* query parameters. If a delta
     cannot be produced from that version, the full data set is returned and
     the member *reset* in the object will be set to *true*. In either case,
     the members *session* and *serial* identify the version of the data set
     returned and their values should be passed as the query parameters in a
     future request.

     The members *announced* and *withdrawn* contain arrays with route
     origins that have been announced and withdrawn, respectively, since the
     provided session and serial. If *reset* is *true*, the *withdrawn*
     member is not present.

``/json-delta/notify, /json-delta/notify?session=session&serial=serial``
     Returns a JSON object with two members *session* and *serial* which
     contain the session ID and serial number of the current data set.

     If the *session* and *serial* query parameters are provided, and the
     session ID and serial number of the current data set are identical to
     the provided values, the request will not return until a new data set is
     available. This can be used as a means to get notified when the data set
     has been updated.

The HTTP service supports **POST** requests on the following path:

``/validity``
     Returns a JSON object describing the validity of multiple routes. This
     expects a JSON body in the same format as 
     :ref:`the validate command <validity-checker:Reading Input From a File>`.
     Also make sure to set the ``Content-Type`` header to ``application/json``
     when sending the request. The request body size is limited to 100 kB. The
     output format matches that of the validate command.

In addition, the ``/log`` endpoint returns :doc:`logging<logging>`
information and the ``/metrics``, ``/status`` and
``/version`` endpoints provide :doc:`monitoring<monitoring>` data.

.. versionadded:: 0.9.0
   The ``/json-delta`` path
.. versionchanged:: 0.9.0
   The ``/api/v1/status`` path
.. versionadded:: 0.13.0
   The ``/json-delta/notify`` path
.. versionadded:: 0.15.0
   The ``/validity`` POST endpoint