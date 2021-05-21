Glossary
========

.. glossary::
  :sorted:

  Route Origin Attestation (ROA)
    A cryptographically signed object that contains a statement authorising a
    *single* Autonomous System Number (ASN) to originate one or more IP
    prefixes, along with their maximum prefix length. A ROA can only be created
    by the legitimate holder of the IP prefixes contained within it.
    
  Validated ROA Payload (VRP)
    RPKI Relying Party software performs cryptographic verification on all
    published :term:`ROAs <Route Origin Attestation (ROA)>`. If everything
    checks out, the software will produce one or more validated ROA payloads
    (VRPs) for each ROA, depending on how many IP prefixes are contained with in
    it. Each VRP is a tuple of an ASN, a single prefix and its maximum prefix
    length. If verification fails, the ROA is discarded and it'll be like no
    statement was ever made. 

  Resource Public Key Infrastructure (RPKI)
    RPKI proves the association between specific IP address blocks or Autonomous
    System Numbers (ASNs) and the holders of those Internet number resources.
    The certificates are proof of the resource holder's right of use of their
    resources and can be validated cryptographically. RPKI is based on an X.509
    certificate profile defined in :RFC:`3779`. Using RPKI to support secure
    Internet routing is described in :rfc:`6480`. 
    
  RPKI-to-Router (RPKI-RTR)
    The RPKI to Router protocol provides a simple but reliable mechanism for 
    routers to receive RPKI prefix origin data from a trusted cache. It is 
    standardised in :rfc:`6810` (v0) and :rfc:`8210` (v1).
    
  Route Origin Validation (ROV)
    A mechanism by which route advertisements can be authenticated as 
    originating from an expected, authorised Autonomous System (AS).
    
  Maximum Prefix Length (MaxLength)
    The most specific announcement of an IP prefix an Autonomous System is
    authorised to do according to the published :term:`ROA <Route Origin
    Attestation (ROA)>`.
    
  RPKI Relying Parties
    Those who want to use a Public Key Infrastructure (PKI) to validate 
    digitally signed attestations.
    
  Trust Anchor (TA)
    Each of the five Regional Internet Registries (RIRs) publishes a trust
    anchor  that includes all resources (a ‘0/0’ self-signed X.509 CA
    certificate). They issue a child certificate containing all the resources
    that are held and managed by the RIR. 
  
  Trust Anchor Locator (TAL)
    The Trust Anchor Locator (TAL) is used to retrieve and verify the
    authenticity of a :term:`trust anchor <Trust Anchor (TA)>`. Specified in
    :rfc:`8630`, a TAL contains one or more URIs pointing to the RIR root
    certificate, as well as the public key of the trust anchor in DER format,
    encoded in Base64. The TAL is constant so long as the trust anchor's public
    key and its location do not change.
    
  Repository
    The RPKI repository system consists of multiple distributed and delegated 
    repository :term:`publication points <Publication Point>`. Each repository
    publication point is associated with one or more RPKI certificates'
    publication points. 
    
  RPKI Repository Delta Protocol (RRDP)
    Described in :rfc:`8182`, RRDP is a repository access protocol based on
    Update Notification, Snapshot, and Delta Files that a :term:`Relying Party
    <RPKI Relying Parties>` can retrieve over the HTTPS protocol.
    
  Publication Point
    RPKI does not use a single repository publication point to publish RPKI
    objects. Instead, the RPKI repository system consists of multiple
    distributed and delegated repository publication points. In practice this
    means that when running a certificate authority, an CA operator can either
    publish all cryptographic material themselves, or they can rely on a third
    party for publication.

  Manifest
    A manifest is a signed object that contains a listing of all the signed
    objects in the repository publication point associated with an authority
    responsible for publishing in the repository. Refer to :rfc:`6486` for more
    infromation.
    
  Certificate Revocation List (CRL)
    A list of digital certificates that have been revoked by the issuing
    Certificate Authority (CA) before their scheduled expiration date and should
    no longer be trusted. Each entry in a Certificate Revocation List includes
    the serial number of the revoked certificate and the revocation date. The
    CRL file is signed by the CA to prevent tampering. The RPKI CRL profile is 
    defined in :rfc:`6487`.
    
  Stale Objects
    In RPKI, manifests and :term:`CRLs <Certificate Revocation List (CRL)>` can
    be stale if the time given in their ``next-update`` field is in the past,
    indicating that an update to the object was scheduled but didn't happen. This
    can be because of an operational issue at the issuer or an attacker trying to
    replay old objects. 
    
  Unsafe VRPs
    If the address prefix of a :term:`VRP <Validated ROA Payload (VRP)>`
    overlaps with any resources assigned to a CA that has been rejected because
    if failed to validate completely, the VRP is said to be *unsafe* since using
    it may lead to legitimate routes being flagged as RPKI Invalid.
  