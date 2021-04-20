.. _doc_routinator_interactive:

Running Interactively
=====================

Routinator can perform RPKI validation as a one-time operation and print a
Validated ROA Payload (VRP) list in various formats, or it can return the
validity of a specific announcement. These functions are accessible on the
command line via the following sub-commands:

:subcmd:`vrps`
     Fetches RPKI data and produces a Validated ROA Payload (VRP) list in the
     specified format.

:subcmd:`validate`
     Outputs the RPKI validity for a specific announcement by supplying Routinator
     with an ASN and a prefix.

Printing a List of VRPs
-----------------------

Routinator can produce a Validated ROA Payload (VRP) list in many different formats,
which are either printed to standard output or saved to a file:

csv
      The list is formatted as lines of comma-separated values of the prefix in
      slash notation, the maximum prefix length, the autonomous system number,
      and an abbreviation for the trust anchor the entry is derived from. The
      latter is the name of the TAL file  without the extension *.tal*. This is
      the default format used if the :option:`--format` or :option:`-f` option
      is missing.
csvcompat
       The same as csv except that all fields are embedded in double
       quotes and the autonomous system number is given without the
       prefix AS. This format is pretty much identical to the CSV
       produced by the RIPE NCC Validator.
csvext
      This is an extended version of the *csv* format, which was used by the RIPE
      NCC RPKI Validator 1.x. Each line contains these comma-separated values: the
      rsync URI of the ROA the line is taken from (or "N/A" if it isn't from a ROA),
      the autonomous system number, the prefix in slash notation, the maximum prefix
      length, and lastly the not-before and not-after date of the validity of the ROA.
json
      The list is placed into a JSON object with a single  element *roas* which
      contains an array of objects with four elements each: The autonomous system
      number of  the  network  authorised to originate a prefix in *asn*, the prefix
      in slash notation in *prefix*, the maximum prefix length of the announced route
      in *maxLength*, and the trust anchor from which the authorisation was derived
      in *ta*. This format is identical to that produced by the RIPE NCC Validator
      except for different naming of the trust anchor. Routinator uses the name
      of the TAL file without the extension *.tal* whereas the RIPE NCC Validator
      has a dedicated name for each.
openbgpd
      Choosing  this format causes Routinator to produce a *roa-set*
      configuration item for the OpenBGPD configuration.
bird
      Choosing this format causes Routinator to produce a roa table
      configuration item for the BIRD configuration.

bird2
      Choosing this format causes Routinator to produce a route table
      configuration item for the BIRD2 configuration.
rpsl
      This format produces a list of RPSL objects with the authorisation in the
      fields *route*, *origin*, and *source*. In addition, the fields *descr*,
      *mnt-by*, *created*, and *last-modified*, are present with more or less
      meaningful values.
summary
      This format produces a summary of the content of the RPKI repository. For
      each trust anchor, it will print the number of verified ROAs and VRPs. Note
      that this format does not take filters into account. It will always provide
      numbers for the complete repository.

For example, to get the validated ROA payloads in CSV format, run:

.. code-block:: bash

   routinator vrps --format csv
   ASN,IP Prefix,Max Length,Trust Anchor
   AS55803,103.14.64.0/23,23,apnic
   AS267868,45.176.192.0/24,24,lacnic
   AS41152,82.115.18.0/23,23,ripe
   AS28920,185.103.228.0/22,22,ripe
   AS11845,209.203.0.0/18,24,afrinic
   AS63297,23.179.0.0/24,24,arin
   ...

To generate a file with with the validated ROA payloads in JSON format, run:

.. code-block:: bash

   routinator vrps --format json --output authorisedroutes.json

Filtering
"""""""""

In case you are looking for specific information in the output, Routinator
allows filtering to see if a prefix or ASN is covered or matched by a VRP. You
can do this using the :option:`--filter-asn` and :option:`--filter-prefix`
options.

When using :option:`--filter-asn`, you can use both ``AS64511`` and ``64511`` as
the notation. With :option:`--filter-prefix`, the result will include VRPs
regardless of their ASN and MaxLength. Both filter flags can be combined and
used multiple times in a single query and will be treated as a logical *"or"*.

A validation run will be started before returning the result, making sure you
get the latest information. If you would like a result from the current cache,
you can use the :option:`--noupdate` or :option:`-n` option.

Here are some examples filtering for an ASN and prefix in CSV and JSON format:

.. code-block:: bash

   routinator vrps --format csv --filter-asn 196615
   ASN,IP Prefix,Max Length,Trust Anchor
   AS196615,2001:7fb:fd03::/48,48,ripe
   AS196615,93.175.147.0/24,24,ripe

.. code-block:: text

   routinator vrps --format json --filter-prefix 93.175.146.0/24
   {
     "roas": [
       { "asn": "AS12654", "prefix": "93.175.146.0/24", "maxLength": 24, "ta": "ripe" }
     ]
   }

.. _doc_routinator_validity_checker:

Validity Checker
----------------

You can check the RPKI origin validation status of a specific BGP announcement
using the :subcmd:`validate` subcommand and by supplying the ASN and prefix. A
validation run will be started before returning the result, making sure you get
the latest information. If you would like a result from the current cache, you
can use the :option:`--noupdate` or :option:`-n` option.

.. code-block:: bash

   routinator validate --asn 12654 --prefix 93.175.147.0/24
   Invalid

A detailed analysis of the reasoning behind the validation outcome is printed in
JSON format. In case of an Invalid state, whether this because the announcement
is originated by an unauthorised AS, or if the prefix is more specific than the
maximum prefix length allows. Lastly, a complete list of VRPs that caused the
result is included.

.. code-block:: text

   routinator validate --json --asn 12654 --prefix 93.175.147.0/24
   {
     "validated_route": {
      "route": {
        "origin_asn": "AS12654",
        "prefix": "93.175.147.0/24"
      },
      "validity": {
        "state": "Invalid",
        "reason": "as",
        "description": "At least one VRP Covers the Route Prefix, but no VRP ASN matches the route origin ASN",
        "VRPs": {
         "matched": [
         ],
         "unmatched_as": [
           {
            "asn": "AS196615",
            "prefix": "93.175.147.0/24",
            "max_length": "24"
           }

         ],
         "unmatched_length": [
         ]      }
      }
     }
   }

If you run the HTTP service in daemon mode, this information is also available
via the :ref:`user interface <doc_routinator_ui>` and at the ``/validity`` API
endpoint.
