Unsafe VRPs
===========

If the address prefix of a VRP overlaps with any resources assigned to a
Certification Authority (CA) that has been rejected because it failed to
validate completely, the VRP is said to be *unsafe* since using it may lead
to legitimate routes being flagged as RPKI Invalid.

In the Hosted RPKI systems that the five Regional Internet Registries offer,
all certificates and ROAs reside within a single system and all related
objects are published in a single repository. In addition, these systems do
not allow sub-delegation of resources. As a result, relying party software
will normally fetch and validate the entire set of objects, or nothing at
all. This makes the occurrence of unsafe VRPs highly unlikely.

When an organisation runs RPKI with their own CA, they can delegate a subset
of their resources to another party, such as their customer, who in turn runs
their own CA. Both parties can publish in a repository they host themselves,
or one that is offered by a third party as a service. Because there are now
more variables at play, such as broken CAs or unavailable repositories, there
is a possibility of Unsafe VRPs emerging.

Unsafe VRPs typically occur when the organisation that holds the superset of
resources publishes a ROA for their aggregate prefix, e.g. 2001:db8::/32-32,
and the customer publishes a ROA to authorise a more specific, e.g.
2001:db8:abcd:/48-48. Now, when the customer CA is unavailable for any reason
and validation fails, the VRP for 2001:db8:abcd:/48 will be marked as
*unsafe*. Note that the reason for the unavailability can be that the CA
itself is broken, or because repository that hosts the ROA is unavailable for
a prolonged period.

Routinator has an :option:`--unsafe-vrps` option that specifies how to deal
with these types of VRPs. Currently, the default policy is *warn* in order to
gain operational experience with the frequency and impact of unsafe VRPs.
This default may change in future version.