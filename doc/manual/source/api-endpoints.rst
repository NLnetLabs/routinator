API Endpoints
=============

The HTTP service supports **GET** requests on the following paths:

``/api/v1/status``
     Returns exhaustive information in JSON format on all :term:`trust anchors <Trust
     Anchor (TA)>`,
     :term:`repositories <Repository>`, :term:`RRDP <RPKI Repository Delta Protocol
     (RRDP)>` and rsync connections, as well as :term:`RTR <RPKI-to-Router (RPKI-RTR)>`
     and HTTP
     sessions. This data set provides the source for the Routinator user
     interface.

``/api/v1/validity/as-number/prefix``
     Returns a JSON object describing whether the route announcement given by
     its :term:`origin AS` Number and address :term:`prefix <IP prefix>` is :term:`RPKI
     <Resource Public Key Infrastructure (RPKI)>` valid, invalid, or not
     found. A complete list of :term:`VRPs <Validated ROA Payload (VRP)>` that caused the
     result is included. For
     details about its contents see :doc:`validity checker<validity-checker>`.
     
``/validity?asn=as-number&prefix=prefix``
     Same as above but with a more form-friendly calling convention.
     
``/json-delta, /json-delta?session=session&serial=serial``
     Returns a JSON object with the changes since the dataset version
     identified by the *session* and *serial* query parameters. If a delta
     cannot be produced from that version, the full data set is returned and
     the member *reset* in the object will be set to *true*. In either case,
     the members *session* and *serial* identify the version of the data set
     returned and their values should be passed as the query parameters in a
     future request.

     The *announced* and *withdrawn* arrays contain the payloads added and
     removed since the requested version. Each item has a *type* of
     ``routeOrigin``, ``routerKey`` or ``aspa``. An :term:`ASPA <Autonomous System
     Provider Authorisation (ASPA)>` item contains the
     :term:`customer ASN <Customer AS and provider AS>` in ``customerAsn`` and an array of
     :term:`provider ASNs <Customer AS and provider AS>` in
     ``providerAsns``. When *reset* is *true*, *announced* contains the full
     dataset and the response omits *withdrawn*.

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