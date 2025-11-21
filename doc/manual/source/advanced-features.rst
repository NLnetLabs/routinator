Advanced Features
=================

Routinator offers several advanced features to let operators gain operational
experience with some of the ongoing work in the Internet Engineering Task
Force to improve and augment RPKI. 

.. note:: 

    The Hosted RPKI systems that the RIRs offer currently only support the
    creation of ROAs. To manage ASPA, BGPsec or other RPKI objects, you can
    run Delegated RPKI with `Krill <https://krill.docs.nlnetlabs.nl/>`_. 

ASPA
----

Autonomous System Provider Authorisation (ASPA), currently described in two
Internet drafts in the IETF, applies the concepts of authenticated origins we
know from ROAs to the propagation of routes. An ASPA is a digitally signed
object through which the holder of an Autonomous System (AS) can authorise
one or more other ASes as its upstream providers. When validated, an ASPA's
content can be used for detection and mitigation of route leaks.

You can let Routinator process ASPA objects and include them in the published
dataset, as well as the metrics, using the :option:`--enable-aspa` option
or by setting ``enable-aspa`` to True in the :doc:`configuration
file<configuration>`. ASPA information will be exposed via RTR, as well as
in the :term:`json` and :term:`jsonext` output formats, e.g.: 

.. code-block:: json

    {
        "metadata": {
            "generated": 1681829067,
            "generatedTime": "2023-04-18T14:44:27Z"
        },
        "roas": [{
            "asn": "AS196615",
            "prefix": "93.175.147.0/24",
            "maxLength": 24,
            "source": [{
                "type": "roa",
                "uri": "rsync://rpki.ripe.net/repository/DEFAULT/73/fe2d72-c2dd-46c1-9429-e66369649411/1/49sMtcwyAuAW2lVDSQBGhOHd9og.roa",
                "validity": {
                    "notBefore": "2023-01-01T08:44:47Z",
                    "notAfter": "2024-07-01T00:00:00Z"
                },
                "chainValidity": {
                    "notBefore": "2023-04-18T14:32:13Z",
                    "notAfter": "2023-04-20T00:00:00Z"
                },
                "stale": "2023-04-20T00:00:00Z"
            }]
        }],
        "routerKeys": [],
        "aspas": [{
          "customer": "AS64496",
          "afi": "ipv6",
          "providers": ["AS64499", "AS64511", "AS65551"],
          "source": [{
              "type": "aspa",
              "uri": "rsync://acmecorp.example.net/0/AS64496.asa",
              "tal": "ripe",
              "validity": {
                  "notBefore": "2023-04-13T07:21:24Z",
                  "notAfter": "2024-04-11T07:26:24Z"
              },
              "chainValidity": {
                  "notBefore": "2023-04-18T14:32:13Z",
                  "notAfter": "2023-04-20T00:00:00Z"
              },
              "stale": "2023-04-20T00:00:00Z"
            }]
        }]
    }

.. seealso::

    - `A Profile for Autonomous System Provider Authorization
      <https://datatracker.ietf.org/doc/html/draft-ietf-sidrops-aspa-profile>`_
    - `BGP AS_PATH Verification Based on Autonomous System Provider
      Authorization (ASPA) Objects
      <https://datatracker.ietf.org/doc/html/draft-ietf-sidrops-aspa-verification>`_ 
    - `Manage ASPA objects with Krill
      <https://krill.docs.nlnetlabs.nl/en/stable/manage-aspas.html>`_

.. versionadded:: 0.13.0

BGPsec
------

The goal of BGPsec, as described in :RFC:`8209`, is to provide full AS path
validation. For this operators will need to publish BGPsec router keys in the
RPKI. As there is currently very limited deployment, validating these objects
with Routinator is not enabled by default. 

You can let Routinator process router keys and include them in the published
dataset, as well as the metrics, using the :option:`--enable-bgpsec` option
or by setting ``enable-bgpsec`` to True in the :doc:`configuration
file<configuration>`. BGPsec information will be exposed via RTR, as well as
in the :term:`SLURM`, :term:`json` and :term:`jsonext` output formats, e.g.: 

.. code-block:: json 

    {
        "metadata": {
            "generated": 1626853335,
            "generatedTime": "2021-07-21T07:42:15Z"
        },
        "roas": [{
            "asn": "AS196615",
            "prefix": "93.175.147.0/24",
            "maxLength": 24,
            "source": [{
                "type": "roa",
                "uri": "rsync://rpki.ripe.net/repository/DEFAULT/73/fe2d72-c2dd-46c1-9429-e66369649411/1/49sMtcwyAuAW2lVDSQBGhOHd9og.roa",
                "validity": {
                    "notBefore": "2021-01-01T04:39:56Z",
                    "notAfter": "2022-07-01T00:00:00Z"
                },
                "chainValidity": {
                    "notBefore": "2021-05-06T12:51:30Z",
                    "notAfter": "2021-05-08T00:00:00Z"
                },
                "stale": "2021-05-08T00:00:00Z"
            }]
        }],
        "routerKeys": [{
            "asn": "AS64496",
            "SKI": "E2F075EC50E9F2EFCED81D44491D25D42A298D89",
            "routerPublicKey": "kwEwYHKoZIzj0CAtig5-QfEKpTtFgiqfiAFQg--LAQerAH2Mpp-GucoDAGBbhIqMFQYIKoZIzj0DAQcDQgAEgFcjQ_D33wNPsXxnAGb-mtZ7XQrVO9DQ6UlASh",
            "source": [{
                "type": "roa",
                "uri": "rsync://acmecorp.example.net/rpki/RIPE-NLACMECORP/R0tgdREopjYdeyeI-wXUJQ4p786.cer",
                "validity": {
                    "notBefore": "2021-11-09T17:04:40Z",
                    "notAfter": "2022-11-09T17:04:39Z"
                },
                "chainValidity": {
                    "notBefore": "2022-01-16T14:45:51Z",
                    "notAfter": "2021-01-18T00:00:00Z"
                },
                "stale": "2021-01-18T00:00:00Z"
            }]
        }],
        "aspas": []
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
