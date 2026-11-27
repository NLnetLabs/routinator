Unsafe VRPs
===========

Routinator is unique among :term:`relying party <RPKI Relying Parties>` software in its
ability to alert
operators to a subtle condition we refer to as *"Unsafe VRPs"*.  We will
explore that concept here.

If the address :term:`prefix <IP prefix>` of a :term:`Validated ROA Payload (VRP)`
overlaps with any
resources assigned to a :term:`Certification Authority (CA)` that has been rejected
because it failed to validate completely, the VRP is
said to be *unsafe*
since using it may lead to legitimate routes being flagged as :term:`RPKI <Resource Public
Key Infrastructure (RPKI)>` :term:`Invalid`.

In the Hosted RPKI systems that the
five :term:`Regional Internet Registries <Regional Internet Registry (RIR)>` offer,
all certificates and :term:`ROAs <Route Origin Authorisation (ROA)>` reside within a
single system and all related
objects are published in a single :term:`repository`. In addition, these systems do
not allow sub-delegation of resources. As a result, relying party software
will normally fetch and validate the entire set of objects, or in case of an
outage nothing at all. This makes the occurrence of :term:`unsafe VRPs` highly
unlikely.

When an organisation runs RPKI with
their own CA, they can delegate a subset
of their resources to another party, such as their customer, who in turn runs
their own CA. Both parties can publish in a
repository they host themselves,
or one that is offered by a third party as a service. Because there are now
more variables at play, such as broken CAs or
unavailable repositories, there
is a possibility of unsafe VRPs emerging.

For example, a provider publishes a ROA for its
aggregate
``2001:db8::/32`` with a maximum length of 32. Its customer publishes a ROA
authorising its own :term:`AS <Autonomous System (AS)>` to originate
``2001:db8:abcd::/48``. If Routinator
rejects the customer CA, the customer's VRP drops out of the dataset.
The provider's /32 VRP remains and overlaps the
rejected CA's resources.
It is this /32 VRP that Routinator can mark as unsafe.

If the /32 is the only remaining VRP covering the
announcement, a router
performing origin validation will classify the customer's /48 as Invalid:
the /32 covers the prefix but its maximum length is 32. Filtering out that
VRP leaves the announcement :term:`NotFound` because
no :term:`covering VRP` remains.

The :option:`--unsafe-vrps` policy determines how Routinator handles these
overlaps:

* ``accept`` (default) keeps the VRPs without
  counting or logging unsafe VRPs.
* ``warn`` keeps the VRPs, counts them and logs each
  one at info level.
* ``reject`` filters the VRPs out, counts them and
  logs each one at warn level.

With either ``warn`` or ``reject``, Routinator also logs a warning when it
encounters any unsafe VRPs during a validation run.
