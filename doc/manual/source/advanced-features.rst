Advanced Features
=================

Routinator offers several advanced features to let operators gain operational
experience with some of the ongoing work in the Internet Engineering Task
Force to improve and augment RPKI. 

Resource Tagged Attestations
----------------------------

.. versionadded:: 0.8.0

Resource Tagged Attestations (RTAs) allow any arbitrary file to be signed
‘with resources’ by one or more parties. The RTA object is a separate file
that cryptographically connects the document with a set of resources. The
receiver of the object can use Routinator to show these resources, and verify
that it was created by their rightful holder(s).

One practical example where RTA could be valuable is to authorise a Bring
Your Own IP (BYOIP) process, where you bring part or all of your publicly
routable IPv4 or IPv6 address range from your on-premises network to a cloud
provider. The document authorising BYOIP could be signed using RTA.

RTA objects can be generated using Krill, the RPKI Certificate Authority
software from NLnet Labs, and you can use the MyAPNIC hosted service. The
objects can be validated using Routinator if it is built with RTA support,
using the :ref:`features<installation-notes:enabling or disabling features>`
functionality provided by Cargo:

.. code-block:: text

   cargo install --locked --features rta routinator

You can now interactively validate an RTA signed object. If it is valid,
Routinator will report the resources used to sign the object:

.. code-block:: text

    routinator rta acme-corp-byoip.rta
    
    192.0.2.0/24
    203.0.113.0/24
    2001:db8::/48 

.. seealso::

    - `A profile for Resource Tagged Attestations (RTAs)
      <https://datatracker.ietf.org/doc/html/draft-ietf-sidrops-rpki-rta>`_
    - `Moving RPKI Beyond Routing Security
      <https://blog.nlnetlabs.nl/moving-rpki-beyond-routing-security/>`_ 
    - `A proof-of-concept for constructing and validating RTAs
      <https://github.com/APNIC-net/rpki-rta-demo>`_

BGPsec
------

.. versionadded:: 0.11.0

The goal of BGPsec, as described in :RFC:`8209`, is to provide full AS path
validation. For this operators will need to publish BGPsec router keys in the
RPKI. As there is currently very limited deployment, validating these objects
with Routinator is not enabled by default. 

You can let Routinator process router keys and include them in the published
dataset, as well as the metrics, using the :option:`--enable-bgpsec` option
or by setting ``enable-bgpsec`` to True in the :doc:`configuration
file<configuration>`.

In the ``jsonext`` :doc:`output format<output-formats>`, the information will
be placed in a JSON file that contains a member named *routerKeys* which 
contains an array of objects with detailed information, e.g.:

.. code-block:: json 

    "routerKeys": [{
            "asn": "AS65535",
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
                    "notAfter": "2022-08-06T00:00:00Z"
                }
            }]
        },
        {
            "asn": "AS65535",
            "SKI": "7D75C49F1835B858FA98D1134742FBE889B55D0B",
            "routerPublicKey": "l9AQcDQgAE4FxJr0n2bux1uoZIzmxqKuAGUhKnr7VLLDgrE--X1Evl-QWw2kZYvIadPjLuFXp5eHWTNVAN22FUU3db_RKpE2wMFkwEwYHKj0CAQYIKoZIzj0D2",
            "source": [{
                "type": "roa",
                "uri": "rsync://acmecorp.example.net/rpki/RIPE-NLACMECORP/j6mK0R8dC3Nzl9duFcSfSFvoibV.cer",
                "validity": {
                    "notBefore": "2021-08-06T16:02:46Z",
                    "notAfter": "2022-08-06T16:05:44Z"
                },
                "chainValidity": {
                    "notBefore": "2022-01-26T15:45:51Z",
                    "notAfter": "2022-07-01T00:00:00Z"
                }
            }]
        }
    ]
