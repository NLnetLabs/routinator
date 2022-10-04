Unsafe VRPs
===========

Routinator is unique among relying party software in its ability to alert
operators to a subtle condition we refer to as *"Unsafe VRPs"*.  We will
explore that concept here.

If the address prefix of a Validated ROA Payload (VRP) overlaps with any
resources assigned to a Certification Authority (CA) that has been rejected
because it failed to validate completely, the VRP is said to be *unsafe*
since using it may lead to legitimate routes being flagged as RPKI Invalid.

In the Hosted RPKI systems that the five Regional Internet Registries offer,
all certificates and ROAs reside within a single system and all related
objects are published in a single repository. In addition, these systems do
not allow sub-delegation of resources. As a result, relying party software
will normally fetch and validate the entire set of objects, or in case of an
outage nothing at all. This makes the occurrence of unsafe VRPs highly
unlikely.

When an organisation runs RPKI with their own CA, they can delegate a subset
of their resources to another party, such as their customer, who in turn runs
their own CA. Both parties can publish in a repository they host themselves,
or one that is offered by a third party as a service. Because there are now
more variables at play, such as broken CAs or unavailable repositories, there
is a possibility of unsafe VRPs emerging.

Unsafe VRPs typically occur when the organisation that holds the superset of
resources publishes a ROA for their aggregate prefix, e.g. 2001:db8::/32-32,
and the customer publishes a ROA to authorise a more specific, e.g.
2001:db8:abcd:/48-48. Now, when the customer CA is unavailable for any reason
and validation fails, the VRP for 2001:db8:abcd:/48 will be marked as
*unsafe*. Note that the reason for the unavailability can be that the CA
itself is broken, or because the repository that hosts the ROA is unavailable
for a prolonged period.

Routinator has an :option:`--unsafe-vrps` option that specifies how to deal
with unsafe resources when conditions creating unsafe VRPs exist. Currently,
the default policy is to *accept* unsafe VRPs. This means VRPs will not be
analysed for being unsafe at all, nor will any metrics be generated. The
other options are *warn*, which will report any unsafe VRP that was
encountered and *reject*, filtering out VRPs that are marked as unsafe. For
the latter two options metrics are made available.