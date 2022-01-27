Local Exceptions
================

In some cases, you may want to override the global RPKI data set with your
own local exceptions. For example, when a legitimate route announcement is
inadvertently flagged as *invalid* due to a misconfigured ROA, you may want
to temporarily accept it to give the operators an opportunity to resolve the
issue.

You can do this by specifying route origins that should be filtered out of
the output, as well as origins that should be added, in a file using JSON
notation according to the :abbr:`SLURM (Simplified Local Internet Number
Resource Management with the RPKI)` standard specified in :RFC:`8416`.

Here is an example file you can use as a starting point for building your
own:

.. code-block:: json

    {
      "slurmVersion": 1,
      "validationOutputFilters": {
        "prefixFilters": [
          {
            "prefix": "192.0.2.0/24",
            "comment": "All VRPs encompassed by prefix"
          },
          {
            "asn": 64496,
            "comment": "All VRPs matching ASN"
          },
          {
            "prefix": "198.51.100.0/24",
            "asn": 64497,
            "comment": "All VRPs encompassed by prefix, matching ASN"
          }
        ],
        "bgpsecFilters": [
          {
            "asn": 64496,
            "comment": "All keys for ASN"
          },
          {
            "SKI": "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA",
            "comment": "Key matching Router SKI"
          },
          {
            "asn": 64497,
            "SKI": "ZGVhZGJlYXRkZWFkYmVhdGRlYWQ",
            "comment": "Key for ASN matching SKI"
          }
        ]
      },
      "locallyAddedAssertions": {
        "prefixAssertions": [
          {
            "asn": 64496,
            "prefix": "198.51.100.0/24",
            "comment": "My other important route"
          },
          {
            "asn": 64496,
            "prefix": "2001:DB8::/32",
            "maxPrefixLength": 48,
            "comment": "My de-aggregated route"
          }
        ],
        "bgpsecAssertions": [
          {
            "asn": 64496,
            "SKI": "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA",
            "routerPublicKey": "Ymx1YmI"
          }
        ]
      }
    }

Use the :option:`--exceptions` option to refer to your file with local
exceptions. Routinator verify that the JSON itself is valid, as well as the
specified values. The exceptions file will be re-read on every validation
run, so you can simply update the file whenever your exceptions change. 

In the metrics Routinator provides, there are counters indicating how many
VRPs are added and excluded from the final data set as a result of your
exceptions. 