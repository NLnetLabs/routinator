Local Exceptions
================

In some cases, you may want to override the global :term:`RPKI <Resource Public Key
Infrastructure (RPKI)>` data set with your
own local exceptions. For example, when a legitimate route announcement is
inadvertently flagged as :term:`invalid` due to a misconfigured :term:`ROA <Route Origin
Authorisation (ROA)>`, you may want
to temporarily accept it to give the operators an opportunity to resolve the
issue.

You can do this by specifying route origins that should be filtered out of
the output, as well as origins that should be added, in a file using JSON
notation according to the :term:`SLURM <Simplified Local Internet Number Resource
Management with the RPKI (SLURM)>` standard specified in :RFC:`8416`.

You can use this `example file
<https://github.com/NLnetLabs/rpki-rs/blob/main/test-data/slurm/full.json>`_
as a starting point, but you can also build your own exceptions file based on
existing :term:`VRPs <Validated ROA Payload (VRP)>` in the global RPKI data set using the :term:`SLURM` output
format in combination with the :option:`--select-asn` and
:option:`--select-prefix` options. 

.. seealso:: 
  
    - :doc:`interactive`

This command selects the VRPs for origin AS196615
from Routinator's current
dataset and writes their :term:`prefixes <IP prefix>` and :term:`maximum prefix lengths
<Maximum Prefix Length (MaxLength)>` to standard
output as SLURM prefix :term:`assertions <Locally added assertion>`:

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

Use :option:`--exceptions` to specify a local exceptions file. In server
mode, Routinator loads all configured exceptions files at startup. If any
file is missing, unreadable or invalid, the server exits with an error.

Before each validation run, the server reloads the files as a set. If any
file fails to load, Routinator logs the file error and the warning
``Using previously loaded local exceptions.`` Validation continues with the
entire set from the last successful load. Changes to any of the files take
effect only once all files load successfully.

To withdraw a temporary exception, remove its entry and save a valid SLURM
file at the configured path. Deleting the file leaves the previous exception
in effect on the running server and prevents the next server start while the
file is still configured.

.. versionchanged:: 0.15.0
   The server retains the previously loaded exceptions if a reload fails.

In the metrics Routinator provides, there are counters indicating how many
VRPs are added and excluded from the final data set
as a result of your
exceptions. 

Limiting Prefix Length
----------------------

It's possible to set the maximum length of IPv4 and IPv6 prefixes that will
be included in the VRP data set. You can set this with the
:option:`--limit-v4-len` and :option:`--limit-v6-len` options, respectively.

To illustrate this option we'll use an extreme example:

.. code-block:: text

    routinator --limit-v4-len=8 --limit-v6-len=19 vrps

Now, all VRPs will be ignored that have a
prefix with a length that is longer
than /8 IPv4 and /19 IPv6:

.. code-block:: text

    ASN,IP Prefix,Max Length,Trust Anchor
    AS6253,48.0.0.0/8,24,arin
    AS31399,53.0.0.0/8,8,ripe
    AS7922,73.0.0.0/8,8,arin
    AS3320,2003::/19,19,ripe
    AS5511,2a01:c000::/19,48,ripe

Note that only the prefix length itself and not the maximum
prefix length
value of the ROA is considered.

.. versionadded:: 0.12.0