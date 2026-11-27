Glossary
========

.. glossary::
  :sorted:

  Route Origin Authorisation (ROA)
    A signed :term:`RPKI <Resource Public Key Infrastructure (RPKI)>` object in which an
    IP address holder names a single
    :term:`autonomous system (AS)` authorised to originate routes to one or more
    :term:`prefixes <IP prefix>`. For each :term:`prefix <IP prefix>`, the holder can specify a
    :term:`maximum prefix length <Maximum Prefix Length (MaxLength)>` to
    allow more-specific announcements. A ROA with :term:`AS 0 <AS 0 (AS0)>` signals that the
    holder does not intend the specified :term:`prefixes <IP prefix>` to be routed.
    See :rfc:`9582` and :rfc:`7607`.

  Validated ROA Payload (VRP)
    A record containing one :term:`IP prefix`, its :term:`maximum prefix length <Maximum
    Prefix Length (MaxLength)>` and an
    :term:`origin AS` number. Each :term:`prefix <IP prefix>` in a valid :term:`ROA <Route
    Origin
    Authorisation (ROA)>` yields a VRP. An invalid :term:`ROA <Route Origin Authorisation
    (ROA)>` contributes none.
    Other valid :term:`ROAs <Route Origin Authorisation (ROA)>` can independently
    authorise the same announcement.

  Resource Public Key Infrastructure (RPKI)
    A public key infrastructure that binds IP address blocks and :term:`AS numbers
    <Autonomous System Number (ASN)>`
    to public keys through :term:`resource certificates <Resource certificate>`. Resource
    holders can use
    the corresponding private keys to issue certificates or sign statements
    about those resources. :rfc:`6480` describes the architecture.
    :rfc:`6487` defines the certificate profile, which uses the resource
    extensions defined in :rfc:`3779`.

  RPKI-to-Router (RPKI-RTR)
    A protocol that routers use to obtain validated :term:`RPKI <Resource Public Key
    Infrastructure (RPKI)>` data from a cache
    such as Routinator. Version 0 carries :term:`VRPs <Validated ROA Payload
    (VRP)>` (:rfc:`6810`). Version 1 adds :term:`BGPsec router keys <BGPsec router key>`
    (:rfc:`8210`).
    Routinator also supports version 2, which adds :doc:`ASPA <aspa>`
    payloads and is specified in the `RTR version 2 Internet-Draft
    <https://datatracker.ietf.org/doc/draft-ietf-sidrops-8210bis/>`_.

  Route Origin Validation (ROV)
    A check of the :term:`prefix <IP prefix>` and :term:`origin AS` in a :term:`BGP
    <Border Gateway Protocol (BGP)>` announcement against the
    available :term:`VRPs <Validated ROA Payload (VRP)>`. The result is
    :term:`Valid` if at least one :term:`covering VRP` matches the :term:`origin AS` and permits
    the announced :term:`prefix <IP prefix>` length. It is :term:`Invalid` if
    :term:`covering VRPs <Covering VRP>` exist
    but none matches, and :term:`NotFound` if no :term:`VRP <Validated ROA Payload (VRP)>`
    covers the :term:`prefix <IP prefix>`. A :term:`Valid`
    result establishes that the origin is authorised. The check does not
    authenticate the :term:`BGP <Border Gateway Protocol (BGP)>` update or verify its
    :term:`AS path <AS path (AS_PATH)>`. See :rfc:`6811`.

  Maximum Prefix Length (MaxLength)
    The longest :term:`prefix <IP prefix>` length authorised for a particular
    :term:`prefix <IP prefix>` in a
    :term:`ROA <Route Origin Authorisation (ROA)>`. For example, a /24 with
    a maximum length of 25 authorises the named :term:`AS <Autonomous System (AS)>` to
    announce the /24
    itself and either of its two /25s. If the :term:`ROA <Route Origin Authorisation
    (ROA)>` omits ``maxLength`` for
    a :term:`prefix <IP prefix>`, only the exact :term:`prefix <IP prefix>` is authorised
    by that entry.

  RPKI Relying Parties
    Operators or systems that rely on validated :term:`RPKI <Resource Public Key
    Infrastructure (RPKI)>` data. Relying party
    software such as Routinator starts from configured :term:`trust anchors
    <Trust Anchor (TA)>` and validates :term:`resource certificates <Resource
    certificate>` and :term:`signed
    objects <RPKI signed object>` before making the resulting data available for use.

  Trust Anchor (TA)
    A trusted starting point for validating an :term:`RPKI <Resource Public Key
    Infrastructure (RPKI)>` :term:`certificate chain <Certification path>`.
    Each of the five :term:`Regional Internet Registries <Regional Internet Registry
    (RIR)>` operates a trust anchor
    represented by a self-signed :term:`CA <Certification authority (CA)>` certificate. A
    :term:`relying party <RPKI Relying Parties>` uses the
    public key in its configured :term:`TAL <Trust Anchor Locator (TAL)>`
    to verify the trust anchor certificate.

  Trust Anchor Locator (TAL)
    A file containing the public key of a :term:`trust anchor <Trust Anchor
    (TA)>` and one or more URIs from which its :term:`CA <Certification authority (CA)>`
    certificate can be
    retrieved. The :term:`relying party <RPKI Relying Parties>` checks that the
    certificate's public key
    matches the key in the trusted TAL. The certificate can therefore be
    renewed at the same location with the same key without changing the TAL.
    See :rfc:`8630`.

  Repository
    A service that makes :term:`RPKI <Resource Public Key Infrastructure (RPKI)>`
    certificates, revocation lists and :term:`signed
    objects <RPKI signed object>` available to :term:`relying parties <RPKI Relying
    Parties>`. A repository can host
    :term:`publication points <Publication Point>` for multiple
    :term:`certification authorities <Certification authority (CA)>` (:term:`CAs
    <Certification authority (CA)>`). See :rfc:`6481`.

  RPKI Repository Delta Protocol (RRDP)
    A protocol for synchronising a :term:`relying party <RPKI Relying Parties>`'s local
    copy of an :term:`RPKI <Resource Public Key Infrastructure (RPKI)>`
    :term:`repository <Repository>` over HTTPS. The :term:`relying party <RPKI Relying
    Parties>` checks a
    :term:`notification file <RRDP notification file>` to see whether its copy is current,
    can be brought
    up to date with :term:`deltas <RRDP delta>`, or needs a full :term:`snapshot <RRDP
    snapshot>`. See :rfc:`8182`.

  Publication Point
    A directory in an :term:`RPKI <Resource Public Key Infrastructure (RPKI)>`
    :term:`repository <Repository>` where a
    :term:`certification authority <Certification authority (CA)>` publishes its products,
    including its
    :term:`manifest <Manifest>` and revocation list. During a :term:`key rollover <CA key
    rollover>`,
    two :term:`CA <Certification authority (CA)>` instances can share a publication point,
    each with its own
    :term:`manifest`. See :rfc:`9286`.

  Manifest
    A signed :term:`RPKI <Resource Public Key Infrastructure (RPKI)>` object that lists
    filenames and hashes for the files a :term:`CA <Certification authority (CA)>`
    instance publishes at its :term:`publication point <Publication Point>`.
    It lists the certificates the :term:`CA <Certification authority (CA)>` issues and
    publishes, its current
    revocation list and its other published :term:`signed objects <RPKI signed object>`.
    The manifest
    excludes itself. A :term:`relying party <RPKI Relying Parties>` can use it to detect
    missing files or
    files whose contents differ from those the :term:`CA <Certification authority (CA)>`
    published. See :rfc:`9286`.

  Certificate Revocation List (CRL)
    A signed list in which a :term:`certification authority <Certification authority
    (CA)>` identifies certificates
    it has revoked by their serial numbers and gives the date of each
    revocation. A :term:`relying party <RPKI Relying Parties>` checks the :term:`CA
    <Certification authority (CA)>`'s signature to verify the
    origin and integrity of the list. See :rfc:`6487`.

  Stale Object
    A :term:`manifest <Manifest>` or :term:`CRL <Certificate Revocation List
    (CRL)>` whose ``nextUpdate`` time has passed. A newer copy may already
    have been published even if the :term:`relying party <RPKI Relying Parties>` has yet
    to retrieve it.

  Unsafe VRPs
    Routinator's term for otherwise valid :term:`VRPs <Validated ROA Payload
    (VRP)>` whose :term:`prefixes <IP prefix>` overlap address space assigned to a
    rejected :term:`CA <Certification authority (CA)>`.
    A :term:`VRP <Validated ROA Payload (VRP)>` that remains in the data set may cover a
    legitimate announcement
    whose authorising :term:`VRP <Validated ROA Payload (VRP)>` was lost when the
    :term:`CA <Certification authority (CA)>` was rejected. This can cause
    the announcement to be classified as :term:`Invalid`. By default Routinator
    keeps these :term:`VRPs <Validated ROA Payload (VRP)>` without counting or logging
    them as unsafe.
    See :doc:`unsafe-vrps` for an example and the available policies.

  Ghostbusters Record (GBR)
    A signed :term:`RPKI <Resource Public Key Infrastructure (RPKI)>` object containing
    contact details for a :term:`resource
    certificate <Resource certificate>` holder in a restricted vCard format (:rfc:`6493`).
    Routinator
    validates the :term:`signed object <RPKI signed object>` and its certificate and
    reports counts of
    valid and invalid records. It does not parse the vCard or verify the
    contact details.

  Autonomous System (AS)
    A group of networks that presents a common routing policy to other
    networks. An AS exchanges reachability information with neighbouring
    ASes using :term:`BGP <Border Gateway Protocol (BGP)>`. See :rfc:`4271`.

  Autonomous System Number (ASN)
    The numeric identifier of an :term:`autonomous system <Autonomous System (AS)>`. In a
    :term:`ROA <Route Origin Authorisation (ROA)>` it identifies
    the authorised origin. In an :term:`ASPA <Autonomous System Provider Authorisation
    (ASPA)>` it identifies the customer or one of
    its providers. Four-octet AS numbers are described in :rfc:`6793`.

  AS 0 (AS0)
    A reserved :term:`AS number <Autonomous System Number (ASN)>` that cannot be used by a
    :term:`BGP <Border Gateway Protocol (BGP)>` speaker as its own
    :term:`ASN <Autonomous System Number (ASN)>` or appear in a valid :term:`BGP <Border
    Gateway Protocol (BGP)>` :term:`AS path <AS path (AS_PATH)>`. An AS 0 :term:`ROA
    <Route Origin Authorisation (ROA)>` signals that the
    holder does not intend the covered :term:`prefixes <IP prefix>` to be routed. Another
    :term:`ROA <Route Origin Authorisation (ROA)>`
    can still authorise an announcement that it covers. In an :doc:`ASPA
    <aspa>`, AS 0 alone in the provider list declares that the customer
    has no providers. See :rfc:`6483` and :rfc:`7607`.

  Border Gateway Protocol (BGP)
    The protocol that networks use to exchange routes. A BGP announcement
    describes the destinations reachable through a neighbour and carries
    attributes used in route selection, including the :term:`AS path <AS path (AS_PATH)>`. See
    :rfc:`4271`.

  AS path (AS_PATH)
    A :term:`BGP <Border Gateway Protocol (BGP)>` attribute that records :term:`AS numbers
    <Autonomous System Number (ASN)>` as a route is propagated.
    For a path consisting of a sequence of :term:`AS numbers <Autonomous System Number
    (ASN)>`, the rightmost one
    is the origin and a neighbour advertising the route normally prepends
    its own :term:`ASN <Autonomous System Number (ASN)>` on the left. See :rfc:`4271` and
    :rfc:`6811`.

  Origin AS
    The :term:`autonomous system <Autonomous System (AS)>` identified as originating a
    :term:`BGP <Border Gateway Protocol (BGP)>` route. :term:`Route
    origin validation <Route Origin Validation (ROV)>` compares its :term:`ASN <Autonomous
    System Number (ASN)>` and the announced :term:`prefix <IP prefix>` with the
    available :term:`VRPs <Validated ROA Payload (VRP)>`. See :rfc:`6811`.

  IP prefix
    A block of IPv4 or IPv6 addresses identified by their common leading
    bits. The number after the slash is the prefix length. For example,
    192.0.2.0/24 represents the addresses sharing the first 24 bits of
    192.0.2.0. See :rfc:`4632` and :rfc:`4291`.

  Covering VRP
    A :term:`VRP <Validated ROA Payload (VRP)>` whose :term:`prefix <IP prefix>` contains
    the entire announced :term:`prefix <IP prefix>`, including an
    exact :term:`prefix <IP prefix>` match. Coverage depends only on the :term:`prefixes
    <IP prefix>`. For the :term:`VRP <Validated ROA Payload (VRP)>`
    to match the announcement, its :term:`ASN <Autonomous System Number (ASN)>` must also
    match the origin and its
    maximum length must permit the announced :term:`prefix <IP prefix>` length. See :rfc:`6811`.

  Valid
    The :term:`route origin validation <Route Origin Validation (ROV)>` state for an
    announcement that matches at
    least one :term:`VRP <Validated ROA Payload (VRP)>`. Other :term:`covering VRPs
    <Covering VRP>` can disagree without changing this
    result. See :rfc:`6811`.

  Invalid
    The :term:`route origin validation <Route Origin Validation (ROV)>` state for an
    announcement covered by one
    or more :term:`VRPs <Validated ROA Payload (VRP)>` when none permits both its
    :term:`origin AS` and its :term:`prefix <IP prefix>`
    length. This result alone does not establish why the mismatch occurred.
    See :rfc:`6811`.

  NotFound
    The :term:`route origin validation <Route Origin Validation (ROV)>` state for an
    announcement whose :term:`prefix <IP prefix>`
    has no :term:`covering VRP` in the data set used for the check. See :rfc:`6811`.

  Route leak
    The propagation of a route beyond its intended scope. For example, a
    customer may advertise a route learned from one provider to another
    provider contrary to their routing policies. The :term:`origin AS` can still
    be authorised by a :term:`ROA <Route Origin Authorisation (ROA)>`. See :rfc:`7908`.

  Autonomous System Provider Authorisation (ASPA)
    A signed :term:`RPKI <Resource Public Key Infrastructure (RPKI)>` object in which a
    :term:`customer AS <Customer AS and provider AS>` identifies its authorised
    :term:`provider ASes <Customer AS and provider AS>`. Routinator validates these
    declarations and makes the
    resulting provider sets available to routers. The object profile and
    the procedures for checking an :term:`AS path <AS path (AS_PATH)>` are separate
    Internet-Drafts.
    See :doc:`aspa` for both specifications and the supported behaviour.

  Customer AS and provider AS
    In an :term:`ASPA <Autonomous System Provider Authorisation (ASPA)>`, the customer AS
    is the :term:`AS <Autonomous System (AS)>` making the declaration. The
    provider AS is an :term:`AS <Autonomous System (AS)>` it authorises to provide
    upstream connectivity.
    A provider list applies to that customer ASN across both IPv4 and
    IPv6. See :doc:`aspa`.

  BGPsec
    An extension to :term:`BGP <Border Gateway Protocol (BGP)>` in which participating
    routers sign path
    information as they propagate a route. A receiving BGPsec speaker
    can verify the signatures using public keys obtained through the
    :term:`RPKI <Resource Public Key Infrastructure (RPKI)>`. Routinator supplies the
    :term:`router keys <BGPsec router key>`. See :rfc:`8205`.

  BGPsec router certificate
    An :term:`RPKI <Resource Public Key Infrastructure (RPKI)>` :term:`end-entity
    certificate <End-entity (EE) certificate>` binding a :term:`BGPsec` public key to one
    or more :term:`AS numbers <Autonomous System Number (ASN)>`. It lets a :term:`BGPsec`
    speaker verify a path signature
    under the authority of the corresponding :term:`AS <Autonomous System (AS)>`. See
    :rfc:`8209`.

  BGPsec router key
    The public key used to verify a :term:`BGPsec` signature. An :term:`RTR
    <RPKI-to-Router (RPKI-RTR)>` router key
    record associates it with an :term:`ASN <Autonomous System Number (ASN)>` and a
    :term:`subject key identifier <Subject Key Identifier (SKI)>`. See
    :rfc:`8210`.

  Regional Internet Registry (RIR)
    An organisation that manages :term:`Internet number resources` within its
    service region. The five RIRs operate :term:`trust anchors <Trust Anchor (TA)>` for
    the public
    :term:`RPKI <Resource Public Key Infrastructure (RPKI)>`. See :rfc:`6480`.

  Internet number resources
    The IPv4 address blocks, IPv6 address blocks and :term:`AS numbers <Autonomous System
    Number (ASN)>` covered
    by :term:`RPKI <Resource Public Key Infrastructure (RPKI)>` :term:`resource
    certificates <Resource certificate>`. See :rfc:`3779` and :rfc:`6480`.

  Resource certificate
    An X.509 certificate that binds a public key to IP address blocks
    or :term:`AS numbers <Autonomous System Number (ASN)>`. During validation, a
    :term:`relying party <RPKI Relying Parties>` checks the
    certificate and the resources it covers along the :term:`certification path`.
    See :rfc:`6487`.

  Certification authority (CA)
    An entity that issues and revokes certificates. In the :term:`RPKI <Resource Public
    Key Infrastructure (RPKI)>` a CA
    can delegate resources by issuing a child CA certificate or issue
    an :term:`end-entity certificate <End-entity (EE) certificate>` for a particular
    purpose. See :rfc:`6487`.

  End-entity (EE) certificate
    A certificate issued for a purpose other than issuing certificates.
    Examples include the certificate embedded in a signed :term:`ROA <Route Origin
    Authorisation (ROA)>` and a
    :term:`BGPsec router certificate`. See :rfc:`6487`, :rfc:`6488` and
    :rfc:`8209`.

  Certification path
    The chain of certificates through which a :term:`relying party <RPKI Relying Parties>`
    validates a
    certificate under a configured :term:`trust anchor <Trust Anchor (TA)>`. An
    :term:`end-entity certificate <End-entity (EE) certificate>`
    can be within its own validity period while a certificate higher in
    the chain has already expired. See :rfc:`5280` and :rfc:`6487`.

  Inherited resources
    Resources that a certificate derives from its issuer for a specified
    resource type instead of listing explicit :term:`prefixes <IP prefix>` or :term:`AS
    numbers <Autonomous System Number (ASN)>`.
    Whether inheritance is permitted depends on the certificate's purpose.
    See :rfc:`3779` and :rfc:`6487`.

  Certificate validity period
    The interval from a certificate's ``notBefore`` time through its
    ``notAfter`` time, inclusive. A certificate within this interval
    must still pass the other validation checks, including checks for
    revocation. See :rfc:`5280`.

  Subject Key Identifier (SKI)
    A value identifying the public key in a certificate. In :term:`BGPsec`, the
    signer includes the SKI so that a verifier can select the appropriate
    :term:`router key <BGPsec router key>` for the signing :term:`AS <Autonomous System
    (AS)>`. See :rfc:`6487` and :rfc:`8205`.

  RPKI signed object
    A digitally signed statement with a content type and a corresponding
    profile, such as a :term:`ROA <Route Origin Authorisation (ROA)>` or a
    :term:`manifest`. It carries the :term:`end-entity
    certificate <End-entity (EE) certificate>` needed to check the signature. Validation
    also checks
    the :term:`certification path` and the rules for that object type.
    See :rfc:`6488`.

  Cryptographic Message Syntax (CMS)
    A format for wrapping content with cryptographic information. :term:`RPKI
    signed objects <RPKI signed object>` use the CMS SignedData structure to carry the content,
    signature and signer's certificate. See :rfc:`5652` and :rfc:`6488`.

  Basic Encoding Rules (BER) and Distinguished Encoding Rules (DER)
    Rules for encoding :term:`ASN <Autonomous System Number (ASN)>`.1 data structures as
    bytes. BER allows several
    ways to encode certain values. DER restricts those choices to a single
    encoding for each value. The :term:`RPKI signed object` profile specifies DER.
    See :rfc:`6488`.

  RPKI Signed Checklist (RSC)
    A :term:`signed object <RPKI signed object>` binding a set of file digests to
    :term:`Internet number
    resources <Internet number resources>`. A verifier can check that separately supplied
    files match
    those digests and that the signer held the listed resources. Routinator
    performs this check with the ``rsc`` command. See :rfc:`9323`.

  Manifest number
    An integer that a :term:`CA <Certification authority (CA)>` increases each time it
    issues a new :term:`manifest` for
    the same key. :term:`Relying parties <RPKI Relying Parties>` can use it to recognise
    an older :term:`manifest`
    at a :term:`publication point`. See :rfc:`9286` and :doc:`data-processing`.

  thisUpdate and nextUpdate
    Fields that give the issue time of a :term:`manifest` or :term:`CRL <Certificate
    Revocation List (CRL)>` and the time by
    which the issuer expects to issue its successor. They let a :term:`relying
    party <RPKI Relying Parties>` assess the freshness of the copy it has retrieved. See
    :rfc:`9286` and :rfc:`6487`.

  rsync URI
    A :term:`repository` address beginning with ``rsync://`` that identifies an
    :term:`RPKI <Resource Public Key Infrastructure (RPKI)>` file or directory.
    :term:`RRDP <RPKI Repository Delta Protocol (RRDP)>` also uses rsync URIs to identify
    the
    objects it transfers over HTTPS, so an object's URI alone does not
    tell you which protocol Routinator used to fetch it. See :rfc:`5781`
    and :rfc:`8182`.

  RRDP notification file
    The file a :term:`relying party <RPKI Relying Parties>` retrieves first when
    synchronising with an
    :term:`RRDP <RPKI Repository Delta Protocol (RRDP)>` :term:`repository`. It contains
    the current session ID and serial number
    and gives the locations and hashes of the :term:`snapshot <RRDP snapshot>` and available
    :term:`deltas <RRDP delta>`. See :rfc:`8182`.

  RRDP snapshot
    A file containing the full set of published objects for one :term:`RRDP <RPKI
    Repository Delta Protocol (RRDP)>`
    :term:`repository` session at a particular serial number. A :term:`relying party <RPKI
    Relying Parties>`
    uses it to initialise its copy or recover when it cannot catch up
    using :term:`deltas <RRDP delta>`. See :rfc:`8182`.

  RRDP delta
    A file describing the publications, replacements and withdrawals
    needed to advance a :term:`repository` copy by one serial number within an
    :term:`RRDP <RPKI Repository Delta Protocol (RRDP)>` session. A :term:`relying party
    <RPKI Relying Parties>` can apply consecutive deltas in order.
    See :rfc:`8182`.

  RRDP session ID and serial number
    The pair identifying a version of an :term:`RRDP <RPKI Repository Delta Protocol
    (RRDP)>` :term:`repository`. The session ID
    identifies the update history and the serial advances as the :term:`repository`
    changes. A new session requires the :term:`relying party <RPKI Relying Parties>` to
    retrieve a
    :term:`snapshot <RRDP snapshot>`. See :rfc:`8182`.

  RTR cache
    A service that supplies processed :term:`RPKI <Resource Public Key Infrastructure
    (RPKI)>` data to routers over :term:`RTR <RPKI-to-Router (RPKI-RTR)>`.
    Routinator can act as the cache for several routers. Each router
    uses the received data according to its routing policy. See
    :rfc:`8210` and :doc:`rtr-service`.

  RTR session ID and serial number
    The pair identifying a version of the data a cache serves over :term:`RTR
    <RPKI-to-Router (RPKI-RTR)>`.
    A router presents its last session ID and serial number to request
    changes. If the cache cannot supply those changes, the router needs
    the full data set. The values are independent of the session IDs and
    serial numbers of :term:`RRDP <RPKI Repository Delta Protocol (RRDP)>`
    :term:`repositories <Repository>`. See :rfc:`8210`.

  RTR refresh, retry and expire intervals
    Timers governing a router's copy of an :term:`RTR cache`'s data. Refresh
    determines when to poll for updates, retry determines when to try
    again after a failure, and expire limits how long the router may use
    data without a successful update. :term:`RTR <RPKI-to-Router (RPKI-RTR)>` version 1
    introduced signalling
    these values to the router. See :rfc:`8210`.

  Simplified Local Internet Number Resource Management with the RPKI (SLURM)
    A file format for applying local exceptions to :term:`RPKI <Resource Public Key
    Infrastructure (RPKI)>` validation output.
    Version 1 covers :term:`prefix <IP prefix>` authorisations and :term:`BGPsec router
    keys <BGPsec router key>`.
    Routinator also supports :term:`ASPA <Autonomous System Provider Authorisation
    (ASPA)>` exceptions using the version 2
    Internet-Draft described in :doc:`aspa`. See :rfc:`8416` and
    :doc:`local-exceptions`.

  Validation output filter
    A :term:`SLURM <Simplified Local Internet Number Resource Management with the RPKI
    (SLURM)>` rule that removes matching payloads from the local validation
    output. Routinator applies filters before adding :term:`local assertions <Locally
    added assertion>`.
    The published :term:`RPKI <Resource Public Key Infrastructure (RPKI)>` objects remain
    available for validation.
    See :rfc:`8416` and :doc:`local-exceptions`.

  Locally added assertion
    A :term:`SLURM <Simplified Local Internet Number Resource Management with the RPKI
    (SLURM)>` entry that adds data to the output supplied to local consumers.
    Its authority comes from the local operator. For example, an operator
    can supply a :term:`prefix <IP prefix>` authorisation for a router without publishing a
    :term:`ROA <Route Origin Authorisation (ROA)>`. See :rfc:`8416`.

  Routing Policy Specification Language (RPSL)
    A language for describing routing policies and routing registry
    objects. Routinator's RPSL output expresses :term:`prefix <IP prefix>` and :term:`origin AS`
    pairs as route objects. See :rfc:`2622`, :rfc:`4012` and
    :doc:`output-formats`.

  Subject Information Access (SIA)
    A certificate extension that supplies locations for services or objects
    associated with the certificate's subject. In an :term:`RPKI <Resource Public Key
    Infrastructure (RPKI)>` :term:`CA <Certification authority (CA)>` certificate,
    these include the :term:`publication point` and :term:`manifest`. The ``rpkiNotify``
    access method gives the URI of an :term:`RRDP notification file`. See
    :rfc:`6487` and :rfc:`8182`.

  CA key rollover
    The replacement of a :term:`certification authority <Certification authority (CA)>`'s
    key pair. During the
    transition the :term:`CA <Certification authority (CA)>` can publish objects under
    both keys, with a separate
    :term:`manifest` and :term:`CRL <Certificate Revocation List (CRL)>` for each. See
    :rfc:`6489` and :rfc:`9286`.

  Transport Layer Security (TLS)
    A protocol that protects data in transit and can authenticate the
    endpoint presenting a certificate. Routinator uses TLS when fetching
    :term:`RRDP <RPKI Repository Delta Protocol (RRDP)>` files over HTTPS and can serve
    HTTP and :term:`RTR <RPKI-to-Router (RPKI-RTR)>` clients over TLS.
    :term:`RPKI <Resource Public Key Infrastructure (RPKI)>` object signatures are checked
    separately after retrieval.
    See :rfc:`8446` and :doc:`rtr-service`.

  PEM encoding
    A text representation of binary data such as a certificate or private
    key. Base64-encoded data appears between labelled BEGIN and END lines.
    Routinator accepts PEM files when configuring :term:`TLS <Transport Layer Security
    (TLS)>` certificates and
    keys. See :rfc:`7468`.

  Same origin
    Two URLs have the same origin when their schemes, hosts and effective
    ports match. Routinator applies this check to the :term:`snapshot <RRDP snapshot>` and
    :term:`delta <RRDP delta>`
    URLs advertised by an :term:`RRDP notification file`. See :rfc:`6454` and
    :doc:`data-processing`.
