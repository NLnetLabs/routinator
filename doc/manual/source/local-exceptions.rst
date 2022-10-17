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

You can use this `example file
<https://github.com/NLnetLabs/rpki-rs/blob/main/test-data/slurm/full.json>`_
as a starting point, but you can also build your own exceptions file based on
existing VRPs in the global RPKI data set using the :term:`SLURM` output
format in combination with the :option:`--select-asn` and
:option:`--select-prefix` options. 

.. seealso:: 
  
    - :doc:`interactive`

For example, this command will create a SLURM file that always authorises all
announcements that are currently done from AS196615:

.. code-block:: text

    routinator vrps --format slurm --select-asn 196615

The output will look like this:

.. code-block:: json

    {
      "slurmVersion": 1,
      "validationOutputFilters": {
        "prefixFilters": [ ],
        "bgpsecFilters": [ ]
      },
      "locallyAddedAssertions": {
        "prefixAssertions": [
          {
            "asn": 196615,
            "prefix": "93.175.147.0/24",
            "maxPrefixLength": 24,
            "comment": "ripe"
          },
          {
            "asn": 196615,
            "prefix": "2001:7fb:fd03::/48",
            "maxPrefixLength": 48,
            "comment": "ripe"
          },
          {
            "asn": 196615,
            "prefix": "2001:7fb:fd04::/48",
            "maxPrefixLength": 48,
            "comment": "ripe"
          }
        ],
        "bgpsecAssertions": [

        ]
      }
    }

Use the :option:`--exceptions` option to refer to your file with local
exceptions. Routinator verifies that the JSON itself is valid, as well as the
specified values. The exceptions file will be re-read on every validation
run, so you can simply update the file whenever your exceptions change. 

In the metrics Routinator provides, there are counters indicating how many
VRPs are added and excluded from the final data set as a result of your
exceptions. 

Limiting Prefix Length
----------------------

It's possible to set the maximum length of IPv4 and IPv6 prefixes that will
be included in the VRP data set. You can set this with the
:option:`--limit-v4-len` and :option:`--limit-v6-len` options, respectively.

To illustrate this option we'll use an extreme example:

.. code-block:: text

    routinator --limit-v4-len=8 --limit-v6-len=19 vrps

Now, VRPs for prefixes with a longer prefix length than /8 IPv4 and /19 IPv6
will be ignored:

.. code-block:: text

    ASN,IP Prefix,Max Length,Trust Anchor
    AS6253,48.0.0.0/8,24,arin
    AS31399,53.0.0.0/8,8,ripe
    AS7922,73.0.0.0/8,8,arin
    AS3320,2003::/19,19,ripe
    AS5511,2a01:c000::/19,48,ripe

Note that only the prefix length itself and not the maximum prefix length
value of the ROA is considered.

.. versionadded:: 0.12.0