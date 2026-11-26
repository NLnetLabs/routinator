Advanced Features
=================

This page covers specialised uses of RPKI data supported by Routinator:
BGPsec router certificates and Resource Signed Checklists. These capabilities
have different consumers and deployment requirements.

.. note::

    To manage ASPA, BGPsec or other RPKI objects, you can run Delegated RPKI
    with `Krill <https://krill.docs.nlnetlabs.nl/>`_. A growing number of
    hosted RIR systems allow you to manage these objects as well. Check with
    your RIR to find out what is available.

ASPA
----

ASPA is covered on its own :doc:`page <aspa>`, including default processing,
provider authorisations, output formats and requirements for consuming the data.

BGPsec
------

The goal of BGPsec, as described in :RFC:`8209`, is to provide full AS path
validation. For this operators will need to publish BGPsec router keys in the
RPKI. Routinator validates these objects by default from version 0.16.0;
processing can be disabled with :option:`--disable-bgpsec`. Validating router
certificates does not itself enable BGPsec on routers.

Routinator makes validated router keys available over RTR and in the SLURM,
JSON and extended JSON output formats. The following excerpt from
:term:`jsonext` shows the certificate from which a router key was obtained.

.. code-block:: json

    {
        "routerKeys": [{
          "asn": "AS211321",
          "SKI": "17316903F0671229E8808BA8E8AB0105FA915A07",
          "routerPublicKey": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAET10FMBxP6P3r6aG_ICpfsktp7X6ylJIY8Kye6zkQhNOt0y-cRzYngH8MGzY3cXNvZ64z4CpZ22gf4teybGq8ow",
          "source": [{
            "type": "cer",
            "tal": "ripe",
            "uri": "rsync://testbed.krill.cloud/repo/local-testbed-child/0/ROUTER-00033979-17316903F0671229E8808BA8E8AB0105FA915A07.cer",
            "validity": {
              "notBefore": "2022-07-25T20:47:37Z",
              "notAfter": "2023-07-24T20:52:37Z"
            },
            "chainValidity": {
              "notBefore": "2022-07-25T20:47:37Z",
              "notAfter": "2022-07-26T00:00:00Z"
            },
            "stale": "2022-07-26T00:00:00Z"
          }]
        }]
    }

.. seealso::

    - `BGPsec Protocol Specification
      <https://datatracker.ietf.org/doc/html/rfc8205.html>`_
    - `A Profile for BGPsec Router Certificates, Certificate Revocation
      Lists, and Certification Requests
      <https://datatracker.ietf.org/doc/html/rfc8209.html>`_
    - `Manage BGPSec Router Certificates with Krill
      <https://krill.docs.nlnetlabs.nl/en/stable/manage-bgpsec.html>`_

.. versionadded:: 0.11.0

Resource Signed Checklists
--------------------------

Resource Signed Checklists allow any arbitrary file to be signed
‘with resources’. The RSC object is a separate file
that cryptographically connects the document hash(es) with a set of resources. 
The receiver of the object can use Routinator to show these resources, and 
verify that it was created by their rightful holder.

One practical example where RSC could be valuable is to authorise a Bring
Your Own IP (BYOIP) process, where you bring part or all of your publicly
routable IPv4 or IPv6 address range from your on-premises network to a cloud
provider. The document authorising BYOIP could be signed using RSC.

RSC objects can be generated using e.g. the MyAPNIC hosted service. The
objects can be validated using Routinator. If it is valid,
Routinator will report the resources used to sign the object:

.. code-block:: text

    routinator rsc --document a.txt --document b.txt --signature my-rsc.sig

    Validation of these documents succeeded:
    * a.txt
    * b.txt

    It was verified with an RSC with these resources:
    * AS65536-65551
    * AS64496
    * 192.0.2.0/24
    * 2001:DB8::/32

If it is not valid, it will output that and exit with exit code 1:

.. code-block:: text

    routinator rsc --document test2.txt --signature my-sig.sig

    Failed to match document to valid entry in the check list 'test2.txt'.

    The documents listed on this RSC are:
    f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2  test.txt

    Please be aware that RSCs may be bound to a specific file name, and those file names are case sensitive.

.. seealso::

    - `A Profile for RPKI Signed Checklists (RSCs)
      <https://www.rfc-editor.org/rfc/rfc9323.html>`_

.. versionadded:: 0.16.0
