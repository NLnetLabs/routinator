.. _doc_routinator_local_exceptions:

Local Exceptions
================

In some cases, you may want to override the global RPKI data set with your own
local exceptions. For example, when a legitimate route announcement is
inadvertently flagged as *invalid* due to a misconfigured ROA, you may want to
temporarily accept it to give the operators an opportunity to resolve the
issue.

You can do this by specifying route origins that should be filtered out of the
output, as well as origins that should be added, in a file using JSON notation
according to the :abbr:`SLURM (Simplified Local Internet Number Resource
Management with the RPKI)` standard specified in :RFC:`8416`.

A full example file is provided below. This, along with an empty one is
available in the repository at `/test/slurm
<https://github.com/NLnetLabs/routinator/tree/master/test/slurm>`_.

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
         "SKI": "Zm9v",
         "comment": "Key matching Router SKI"
        },
        {
         "asn": 64497,
         "SKI": "YmFy",
         "comment": "Key for ASN 64497 matching Router SKI"
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
         "comment": "My other important de-aggregated routes"
        }
      ],
      "bgpsecAssertions": [
        {
         "asn": 64496,
         "comment" : "My known key for my important ASN",
         "SKI": "<some base64 SKI>",
         "routerPublicKey": "<some base64 public key>"
        }
      ]
     }
   }

Use the :option:`--exceptions` option to refer to your file with local
exceptions. Routinator will re-read that file on every validation run, so you
can simply update the file whenever your exceptions change.

In the metrics Routinator provides, there are counters indicating how many VRPs
are added and excluded from the final data set as a result of your exceptions. 