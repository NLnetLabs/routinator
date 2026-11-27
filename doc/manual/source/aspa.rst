ASPA
====

:term:`Autonomous System Provider Authorisation (ASPA)` lets the holder of an
:term:`Autonomous System Number (ASN)` publish a signed declaration of its authorised
:term:`provider ASes <Customer AS and provider AS>` in the :term:`RPKI <Resource Public
Key Infrastructure (RPKI)>`. Routinator validates these objects and makes their
payloads available to routers and other applications.

:term:`ASPA <Autonomous System Provider Authorisation (ASPA)>` processing is enabled by
default from Routinator 0.16.0. To use this data
for routing decisions, the receiving router or routing software must support
both :term:`ASPA <Autonomous System Provider Authorisation (ASPA)>` data exchange over
:term:`RTR <RPKI-to-Router (RPKI-RTR)>` version 2 and ASPA-based :term:`AS-path <AS path
(AS_PATH)>` verification.
Operators must also configure a routing policy that determines how the
verification results affect route acceptance or preference.

Provider Authorisations and Route Leaks
---------------------------------------

A :term:`Route Origin Authorisation (ROA)` authorises an :term:`AS <Autonomous System
(AS)>` to originate specified :term:`IP
prefixes <IP prefix>`. An :term:`ASPA <Autonomous System Provider Authorisation (ASPA)>`
describes a different relationship: the :term:`provider ASes <Customer AS and provider
AS>`
authorised by a :term:`customer AS <Customer AS and provider AS>`. It does not contain
:term:`IP prefixes <IP prefix>` or :term:`maximum prefix
lengths <Maximum Prefix Length (MaxLength)>`. The provider declaration is not specific to
IPv4 or IPv6.

:term:`ASPA-based <Autonomous System Provider Authorisation (ASPA)>` :term:`AS-path <AS
path (AS_PATH)>` verification uses these declarations to check relationships
along the :term:`AS path <AS path (AS_PATH)>` of a :term:`BGP <Border Gateway Protocol
(BGP)>` announcement. A router implementing these procedures
can use the results to detect :term:`route leaks <Route leak>` and apply its routing policy.
The protection depends on the available authorisations and the verification
procedures; an :term:`ASPA <Autonomous System Provider Authorisation (ASPA)>` does not
cryptographically sign the path taken by an
individual :term:`BGP <Border Gateway Protocol (BGP)>` announcement.

An :term:`AS <Autonomous System (AS)>` with no providers can publish an :term:`ASPA
<Autonomous System Provider Authorisation (ASPA)>` containing only :term:`AS0 <AS 0
(AS0)>` in its provider
list. This is a special declaration that the :term:`AS <Autonomous System (AS)>` has no
providers.

Routinator's Role
-----------------

Routinator retrieves :term:`ASPA <Autonomous System Provider Authorisation (ASPA)>`
objects alongside other :term:`RPKI <Resource Public Key Infrastructure (RPKI)>` objects
and validates
them against the :term:`RPKI <Resource Public Key Infrastructure (RPKI)>` certificate
hierarchy. Successful validation establishes
that the declaration was signed under authority over the :term:`customer ASN <Customer AS
and provider AS>` and
passes the applicable object validation checks. It cannot establish whether
the declared provider relationships reflect the operator's intended
configuration.

Routinator includes :term:`ASPA <Autonomous System Provider Authorisation (ASPA)>` object
validation checks. The :term:`end-entity (EE)
certificate <End-entity (EE) certificate>` must contain exactly the :term:`customer ASN
<Customer AS and provider AS>`, with no :term:`inherited AS
resources <Inherited resources>`, :term:`AS <Autonomous System (AS)>` ranges or IP
resources. :term:`AS0 <AS 0 (AS0)>` cannot be the :term:`customer ASN <Customer AS and
provider AS>`. :term:`AS0 <AS 0 (AS0)>` is
permitted only as the sole entry in the provider list. Routinator also applies
limits to the number of providers, as described below.

Retrieval failures and validation problems can affect which :term:`ASPA <Autonomous System
Provider Authorisation (ASPA)>` payloads are
available, just as they can affect other :term:`RPKI <Resource Public Key Infrastructure
(RPKI)>` data. See :doc:`data-processing`
for the handling of :term:`repository` updates, stored publications and :term:`stale
objects <Stale Object>`.

.. versionadded:: 0.13.0
   :term:`ASPA <Autonomous System Provider Authorisation (ASPA)>` support.

.. versionchanged:: 0.16.0
   :term:`ASPA <Autonomous System Provider Authorisation (ASPA)>` processing is enabled by
   default.

Combining Provider Authorisations
---------------------------------

If several valid :term:`ASPA <Autonomous System Provider Authorisation (ASPA)>` objects
describe the same :term:`customer AS <Customer AS and provider AS>`, Routinator
combines their provider lists into a single set. An :term:`AS0-only <AS 0 (AS0)>`
declaration does
not override other provider authorisations: :term:`AS0 <AS 0 (AS0)>` remains in the
resulting set
only if all contributing declarations contain only :term:`AS0 <AS 0 (AS0)>`.

For example, if one object lists AS64497 and another lists AS64498 for the
same customer, the output contains both providers. An additional AS0-only
object does not remove either provider.

Provider Limits
~~~~~~~~~~~~~~~

Routinator limits the number of providers it processes. For operators, the
important consequence is that exceeding a limit can remove provider
authorisations from the data available to routers. Missing :term:`ASPA <Autonomous System
Provider Authorisation (ASPA)>` data is not a
declaration that an :term:`AS <Autonomous System (AS)>` has no providers, and does not by
itself make a :term:`BGP <Border Gateway Protocol (BGP)>` path
invalid. The effect on routing depends on the remaining :term:`ASPA <Autonomous System
Provider Authorisation (ASPA)>` data, the router's
:term:`AS-path <AS path (AS_PATH)>` verification procedures and the configured routing policy.

The current implementation applies two separate limits:

* An individual :term:`ASPA <Autonomous System Provider Authorisation (ASPA)>` object
  containing more than 10,000 :term:`provider ASNs <Customer AS and provider AS>` is
  rejected. Other accepted objects for the same :term:`customer AS <Customer AS and
  provider AS>` can still
  contribute provider authorisations.
* If the combined set for a :term:`customer AS <Customer AS and provider AS>` contains
  more than 16,380 providers,
  including :term:`local assertions <Locally added assertion>`, Routinator omits the
  entire set from its
  validated payload snapshot. It logs a warning identifying the :term:`customer AS
  <Customer AS and provider AS>`
  and provider count. It does not truncate the set to fit the limit.

When investigating unexpected :term:`ASPA <Autonomous System Provider Authorisation
(ASPA)>` verification results, check Routinator's
logs and the provider data received by the router. In particular, rejecting
an oversized individual object can leave a provider list derived only from
other accepted objects for the same customer. This differs from omitting the
customer's entire provider set and can affect verification results.

Using the Validated Data
------------------------

RTR
~~~

Routinator's :doc:`rtr-service` supports protocol versions 0, 1 and 2.
:term:`ASPA <Autonomous System Provider Authorisation (ASPA)>` payloads require :term:`RTR
<RPKI-to-Router (RPKI-RTR)>` version 2; connections using version 0 or 1 do not
carry them. The consuming software also needs :term:`ASPA-based <Autonomous System
Provider Authorisation (ASPA)>` verification if it
is to use the data for routing decisions.

The :term:`ASPA <Autonomous System Provider Authorisation (ASPA)>` specifications and
:term:`RTR <RPKI-to-Router (RPKI-RTR)>` extensions are evolving. Check the protocol
support of the Routinator release and the consuming software before deployment.
The specifications are linked under `Further Reading`_ below.

JSON Output
~~~~~~~~~~~

Both :term:`json` and :term:`jsonext` include an ``aspas`` array. Each entry
contains a ``customer`` :term:`ASN <Autonomous System Number (ASN)>` and a list of
``providers``. Neither format includes
an ``afi`` field for :term:`ASPA <Autonomous System Provider Authorisation (ASPA)>`.

The following illustrative entry from the ``aspas`` array in ``json`` output
shows the payload and its :term:`trust anchor <Trust Anchor (TA)>`:

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

To disable :term:`ASPA <Autonomous System Provider Authorisation (ASPA)>` processing, use
:option:`--disable-aspa` or set
``enable-aspa = false`` in the configuration file. This controls the processing
of :term:`ASPA <Autonomous System Provider Authorisation (ASPA)>` objects, rather than
enabling or disabling a router's verification
policy.

When retrieving HTTP output, ``exclude=aspas`` omits :term:`ASPA <Autonomous System
Provider Authorisation (ASPA)>` payloads from that
response without disabling :term:`ASPA <Autonomous System Provider Authorisation (ASPA)>`
processing. See :doc:`http-service` for output
selection options.

Local Exceptions with SLURM v2
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Routinator supports exporting :term:`ASPA <Autonomous System Provider Authorisation
(ASPA)>` payloads in the :term:`slurm2` format from
version 0.15.0. Support for reading :term:`SLURM <Simplified Local Internet Number
Resource Management with the RPKI (SLURM)>` v2 exceptions, including :term:`ASPA filters
<Validation output filter>`
and :term:`local assertions <Locally added assertion>`, was added in version 0.16.0. The
``slurm`` output format
uses :term:`SLURM <Simplified Local Internet Number Resource Management with the RPKI
(SLURM)>` v1 and cannot represent :term:`ASPA <Autonomous System Provider Authorisation
(ASPA)>` payloads.

Routinator 0.16.2 uses the :term:`ASPA <Autonomous System Provider Authorisation (ASPA)>`
exception format described in
`draft-ietf-sidrops-aspa-slurm-04
<https://datatracker.ietf.org/doc/html/draft-ietf-sidrops-aspa-slurm-04>`_.
In particular, :term:`ASPA filters <Validation output filter>` identify the customer using
``customerAsn``,
replacing the earlier draft's ``customerAsid``. :term:`Assertions <Locally added
assertion>` use ``customerAsn``
and ``providerAsns``. These field names belong to :term:`SLURM <Simplified Local Internet
Number Resource Management with the RPKI (SLURM)>`; the ``json`` and
``jsonext`` output formats use ``customer`` and ``providers`` instead.

Filters and :term:`assertions <Locally added assertion>` modify the locally supplied
dataset; they do not change
published :term:`ASPA <Autonomous System Provider Authorisation (ASPA)>` objects.
Routinator filters published payloads before adding
:term:`local assertions <Locally added assertion>`. Local provider lists are combined with
any remaining
providers for the same customer, using the :term:`AS0 <AS 0 (AS0)>` handling described above.

To replace a customer's published provider list locally, filter the published
:term:`ASPA <Autonomous System Provider Authorisation (ASPA)>` payloads for that customer
and then add an :term:`assertion <Locally added assertion>` containing the desired
providers. Adding an :term:`assertion <Locally added assertion>` alone does not remove
existing providers.
In particular, adding an :term:`AS0-only <AS 0 (AS0)>` :term:`assertion <Locally added
assertion>` does not override a non-AS0
provider list that remains in the dataset.

:term:`Local assertions <Locally added assertion>` express an operator's decision rather
than a declaration
validated through the public :term:`RPKI <Resource Public Key Infrastructure (RPKI)>`. See
:doc:`local-exceptions` and the
:doc:`manual-page` for exception handling.

Monitoring
~~~~~~~~~~

Logs and :doc:`monitoring` data help identify invalid :term:`ASPA <Autonomous System
Provider Authorisation (ASPA)>` objects and changes
to the payload dataset. The :doc:`prometheus-metrics` reference includes :term:`ASPA
<Autonomous System Provider Authorisation (ASPA)>`
object and payload counts. Monitor the age of completed validation runs and
check that consuming systems receive and use the expected data.

Publishing ASPAs
----------------

To publish provider authorisations, use your :term:`RIR <Regional Internet Registry
(RIR)>`'s hosted :term:`RPKI <Resource Public Key Infrastructure (RPKI)>` service where
supported, or a delegated :term:`RPKI <Resource Public Key Infrastructure (RPKI)>`
:term:`certificate authority <Certification authority (CA)>` such as `Krill
<https://krill.docs.nlnetlabs.nl/en/stable/manage-aspas.html>`_. Check your
:term:`RIR <Regional Internet Registry (RIR)>`'s documentation for availability and
procedures. For guidance on which :term:`ASes <Autonomous System (AS)>`
to include in your provider list, see `Publishing a provider list
<https://rpki.readthedocs.io/en/latest/rpki/aspa.html#publishing-a-provider-list>`_.

Further Reading
---------------

The object profile and :term:`AS-path <AS path (AS_PATH)>` verification procedures are
specified separately:

* `A Profile for Autonomous System Provider Authorization
  <https://datatracker.ietf.org/doc/html/draft-ietf-sidrops-aspa-profile>`_
* `BGP AS_PATH Verification Based on Autonomous System Provider Authorization
  (ASPA) Objects
  <https://datatracker.ietf.org/doc/html/draft-ietf-sidrops-aspa-verification>`_
* `The RPKI to Router Protocol, Version 2
  <https://datatracker.ietf.org/doc/html/draft-ietf-sidrops-8210bis>`_
* `SLURM with RPKI Autonomous System Provider Authorizations
  <https://datatracker.ietf.org/doc/html/draft-ietf-sidrops-aspa-slurm-04>`_

The links to the :term:`ASPA <Autonomous System Provider Authorisation (ASPA)>` profile,
verification procedures and :term:`RTR <RPKI-to-Router (RPKI-RTR)>` specification
above follow their latest revisions. They do not imply that the release
already implements every subsequent change. :term:`SLURM <Simplified Local Internet Number
Resource Management with the RPKI (SLURM)>`'s :term:`ASPA <Autonomous System Provider
Authorisation (ASPA)>` extension is an
Internet-Draft, not a published RFC.
