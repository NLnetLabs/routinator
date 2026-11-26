ASPA
====

Autonomous System Provider Authorisation (ASPA) lets the holder of an
Autonomous System Number (ASN) publish a signed declaration of its authorised
provider ASes in the RPKI. Routinator validates these objects and makes their
payloads available to routers and other applications.

ASPA processing is enabled by default from Routinator 0.16.0. To use this data
for routing decisions, the receiving router or routing software must support
both ASPA data exchange over RTR version 2 and ASPA-based AS-path verification.
Operators must also configure a routing policy that determines how the
verification results affect route acceptance or preference.

Provider Authorisations and Route Leaks
---------------------------------------

A Route Origin Authorisation (ROA) authorises an AS to originate specified IP
prefixes. An ASPA describes a different relationship: the provider ASes
authorised by a customer AS. It does not contain IP prefixes or maximum prefix
lengths. The provider declaration is not specific to IPv4 or IPv6.

ASPA-based AS-path verification uses these declarations to check relationships
along the AS path of a BGP announcement. A router implementing these procedures
can use the results to detect route leaks and apply its routing policy.
The protection depends on the available authorisations and the verification
procedures; an ASPA does not cryptographically sign the path taken by an
individual BGP announcement.

An AS with no providers can publish an ASPA containing only AS0 in its provider
list. This is a special declaration that the AS has no providers.

Routinator's Role
-----------------

Routinator retrieves ASPA objects alongside other RPKI objects and validates
them against the RPKI certificate hierarchy. Successful validation establishes
that the declaration was signed under authority over the customer ASN and
passes the applicable object validation checks. It cannot establish whether
the declared provider relationships reflect the operator's intended
configuration.

Routinator includes ASPA object validation checks. The end-entity (EE)
certificate must contain exactly the customer ASN, with no inherited AS
resources, AS ranges or IP resources. AS0 cannot be the customer ASN. AS0 is
permitted only as the sole entry in the provider list. Routinator also applies
limits to the number of providers, as described below.

Retrieval failures and validation problems can affect which ASPA payloads are
available, just as they can affect other RPKI data. See :doc:`data-processing`
for the handling of repository updates, stored publications and stale objects.

.. versionadded:: 0.13.0
   ASPA support.

.. versionchanged:: 0.16.0
   ASPA processing is enabled by default.

Combining Provider Authorisations
---------------------------------

If several valid ASPA objects describe the same customer AS, Routinator
combines their provider lists into a single set. An AS0-only declaration does
not override other provider authorisations: AS0 remains in the resulting set
only if all contributing declarations contain only AS0.

For example, if one object lists AS64497 and another lists AS64498 for the
same customer, the output contains both providers. An additional AS0-only
object does not remove either provider.

Provider Limits
~~~~~~~~~~~~~~~

Routinator limits the number of providers it processes. For operators, the
important consequence is that exceeding a limit can remove provider
authorisations from the data available to routers. Missing ASPA data is not a
declaration that an AS has no providers, and does not by itself make a BGP path
invalid. The effect on routing depends on the remaining ASPA data, the router's
AS-path verification procedures and the configured routing policy.

The current implementation applies two separate limits:

* An individual ASPA object containing more than 10,000 provider ASNs is
  rejected. Other accepted objects for the same customer AS can still
  contribute provider authorisations.
* If the combined set for a customer AS contains more than 16,380 providers,
  including local assertions, Routinator omits the entire set from its
  validated payload snapshot. It logs a warning identifying the customer AS
  and provider count. It does not truncate the set to fit the limit.

When investigating unexpected ASPA verification results, check Routinator's
logs and the provider data received by the router. In particular, rejecting
an oversized individual object can leave a provider list derived only from
other accepted objects for the same customer. This differs from omitting the
customer's entire provider set and can affect verification results.

Using the Validated Data
------------------------

RTR
~~~

Routinator's :doc:`rtr-service` supports protocol versions 0, 1 and 2.
ASPA payloads require RTR version 2; connections using version 0 or 1 do not
carry them. The consuming software also needs ASPA-based verification if it
is to use the data for routing decisions.

The ASPA specifications and RTR extensions are evolving. Check the protocol
support of the Routinator release and the consuming software before deployment.
The specifications are linked under `Further Reading`_ below.

JSON Output
~~~~~~~~~~~

Both :term:`json` and :term:`jsonext` include an ``aspas`` array. Each entry
contains a ``customer`` ASN and a list of ``providers``. Neither format includes
an ``afi`` field for ASPA.

The following illustrative entry from the ``aspas`` array in ``json`` output
shows the payload and its trust anchor:

.. code-block:: json

   {
       "customer": "AS64496",
       "providers": ["AS64497", "AS64498"],
       "ta": "ripe"
   }

In ``jsonext``, an entry instead has a ``source`` array with information about
the source objects. This illustrative entry shows one source:

.. code-block:: json

   {
       "customer": "AS64496",
       "providers": ["AS64497", "AS64498"],
       "source": [{
           "type": "aspa",
           "uri": "rsync://rpki.example.net/repository/example.asa",
           "tal": "ripe",
           "validity": {
               "notBefore": "2026-11-01T00:00:00Z",
               "notAfter": "2027-11-01T00:00:00Z"
           },
           "chainValidity": {
               "notBefore": "2026-11-01T00:00:00Z",
               "notAfter": "2027-01-01T00:00:00Z"
           },
           "stale": "2026-11-26T00:00:00Z"
       }]
   }

These are individual array entries, not complete output documents or examples
of live authorisations. See :doc:`output-formats` for the surrounding format
and :doc:`http-service` for retrieving data over HTTP.

Operational Controls and Monitoring
-----------------------------------

To disable ASPA processing, use :option:`--disable-aspa` or set
``enable-aspa = false`` in the configuration file. This controls the processing
of ASPA objects, rather than enabling or disabling a router's verification
policy.

When retrieving HTTP output, ``exclude=aspas`` omits ASPA payloads from that
response without disabling ASPA processing. See :doc:`http-service` for output
selection options.

Local Exceptions with SLURM v2
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Routinator supports exporting ASPA payloads in the :term:`slurm2` format from
version 0.15.0. Support for reading SLURM v2 exceptions, including ASPA filters
and local assertions, was added in version 0.16.0. The ``slurm`` output format
uses SLURM v1 and cannot represent ASPA payloads.

Routinator 0.16.2 uses the ASPA exception format described in
`draft-ietf-sidrops-aspa-slurm-04
<https://datatracker.ietf.org/doc/html/draft-ietf-sidrops-aspa-slurm-04>`_.
In particular, ASPA filters identify the customer using ``customerAsn``,
replacing the earlier draft's ``customerAsid``. Assertions use ``customerAsn``
and ``providerAsns``. These field names belong to SLURM; the ``json`` and
``jsonext`` output formats use ``customer`` and ``providers`` instead.

Filters and assertions modify the locally supplied dataset; they do not change
published ASPA objects. Routinator filters published payloads before adding
local assertions. Local provider lists are combined with any remaining
providers for the same customer, using the AS0 handling described above.

To replace a customer's published provider list locally, filter the published
ASPA payloads for that customer and then add an assertion containing the desired
providers. Adding an assertion alone does not remove existing providers.
In particular, adding an AS0-only assertion does not override a non-AS0
provider list that remains in the dataset.

Local assertions express an operator's decision rather than a declaration
validated through the public RPKI. See :doc:`local-exceptions` and the
:doc:`manual-page` for exception handling.

Monitoring
~~~~~~~~~~

Logs and :doc:`monitoring` data help identify invalid ASPA objects and changes
to the payload dataset. The :doc:`prometheus-metrics` reference includes ASPA
object and payload counts. Monitor the age of completed validation runs and
check that consuming systems receive and use the expected data.

Publishing ASPAs
----------------

To publish provider authorisations, use your RIR's hosted RPKI service where
supported, or a delegated RPKI certificate authority such as `Krill
<https://krill.docs.nlnetlabs.nl/en/stable/manage-aspas.html>`_. Check your
RIR's documentation for availability and procedures. For guidance on which ASes
to include in your provider list, see `Publishing a provider list
<https://rpki.readthedocs.io/en/latest/rpki/aspa.html#publishing-a-provider-list>`_.

Further Reading
---------------

The object profile and AS-path verification procedures are specified separately:

* `A Profile for Autonomous System Provider Authorization
  <https://datatracker.ietf.org/doc/html/draft-ietf-sidrops-aspa-profile>`_
* `BGP AS_PATH Verification Based on Autonomous System Provider Authorization
  (ASPA) Objects
  <https://datatracker.ietf.org/doc/html/draft-ietf-sidrops-aspa-verification>`_
* `The RPKI to Router Protocol, Version 2
  <https://datatracker.ietf.org/doc/html/draft-ietf-sidrops-8210bis>`_
* `SLURM with RPKI Autonomous System Provider Authorizations
  <https://datatracker.ietf.org/doc/html/draft-ietf-sidrops-aspa-slurm-04>`_

The links to the ASPA profile, verification procedures and RTR specification
above follow their latest revisions. They do not imply that the release
already implements every subsequent change. SLURM's ASPA extension is an
Internet-Draft, not a published RFC.
