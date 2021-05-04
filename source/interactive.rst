.. _doc_routinator_interactive:

Running Interactively
=====================

Routinator can perform RPKI validation as a one-time operation and print a
validated ROA payload (VRP) list in various formats, or it can return the
validity of a specific announcement. These functions are accessible on the
command line via the following subcommands:

:subcmd:`vrps`
     Fetches RPKI data and produces a Validated ROA Payload (VRP) list in the
     specified format.

:subcmd:`validate`
     Outputs the RPKI validity for a specific announcement by supplying
     Routinator with an ASN and a prefix.

:subcmd:`dump`
     Writes the contents of all stored data to the file system.

Printing a List of VRPs
-----------------------

Routinator can print a list of VRPs by using the :subcmd:`vrps` subcommand and
specifying the :ref:`desired format <doc_routinator_output_formats>`. For
example, to get the VRPs in CSV format, run:

.. code-block:: text

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

.. code-block:: text

   routinator vrps --format json --output authorisedroutes.json

ASN and Prefix Selection
""""""""""""""""""""""""

.. deprecated:: 0.9
   ``--filter-asn`` and ``--filter-prefix``

In case you are looking for specific information in the output, Routinator
allows you to add selectors to see if a prefix or ASN is covered or matched by a
VRP. You can do this using the :option:`--select-asn` and
:option:`--select-prefix` options.

When using :option:`--select-asn`, you can use both ``AS64511`` and ``64511`` as
the notation. With :option:`--select-prefix`, the result will include VRPs
regardless of their ASN and MaxLength. Both selector flags can be combined and
used multiple times in a single query and will be treated as a logical *"or"*.

A validation run will be started before returning the result, making sure you
get the latest information. If you would like a result from the current cache,
you can use the :option:`--noupdate` or :option:`-n` option.

Here are some examples selecting an ASN and prefix in CSV and JSON format:

.. code-block:: text

   routinator vrps --format csv --select-asn 196615
   ASN,IP Prefix,Max Length,Trust Anchor
   AS196615,2001:7fb:fd03::/48,48,ripe
   AS196615,93.175.147.0/24,24,ripe

.. code-block:: text

   routinator vrps --format json --select-prefix 93.175.146.0/24
   {
     "roas": [
       { "asn": "AS12654", "prefix": "93.175.146.0/24", "maxLength": 24, "ta": "ripe" }
     ]
   }

.. _doc_routinator_validity_checker:

Validity Checker
----------------

You can check the RPKI origin validation status of one or more BGP announcements
using the :subcmd:`validate` subcommand and by supplying the ASN and prefix. A
validation run will be started before returning the result, making sure you get
the latest information. If you would like a result from the current cache, you
can use the :option:`--noupdate` option.

.. code-block:: text

   routinator validate --asn 12654 --prefix 93.175.147.0/24
   Invalid

When providing the :option:`--json` option, a detailed analysis of the reasoning
behind the validation outcome is printed in JSON format. In case of an Invalid
state, whether this because the announcement is originated by an unauthorised
AS, or if the prefix is more specific than the maximum prefix length allows.
Lastly, a complete list of VRPs that caused the result is included.

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

If you run the HTTP service in daemon mode, validation information is also
available via the :ref:`user interface <doc_routinator_ui>` and at the
``/validity`` API endpoint.

Reading Input From a File
"""""""""""""""""""""""""

.. versionadded:: 0.9

Routinator can also read input to validate from a file using the
:option:`--input` option. If the file is given as a single dash, input is
read from standard input. You can also save the results to a file using the
:option:`--output` option.

You can provide a simple plain text file with the routes you would like to have
verified by Routinator. The input file should have one route announcement per
line, provided as a prefix followed by an ASCII-art arrow => surrounded by white
space and followed by the AS number of the originating autonomous system.

For example, let's provide Routinator with this file, saved as ``beacons.txt``:

.. code-block:: text

   93.175.147.0/24 => 12654
   2001:7fb:fd02::/48 => 12654

When referring to the file with the :option:`--input` option Routinator
provides the RPKI validity state in the output:

.. code-block:: text

   routinator validate --input beacons.txt 
   93.175.147.0/24 => AS12654: invalid
   2001:7fb:fd02::/48 => AS12654: valid


With the :option:`--json` option you can provide a file in JSON format. It
should consist of a single object with one member *routes*  which contains an
array of objects. Each object describes one route announcement through its
*prefix* and *asn* members which contain a prefix and originating AS number as
strings, respectively.

For example, let's provide Routinator with this ``beacons.json`` JSON file:

.. code-block:: json

  {
    "routes": [{
        "asn": "AS12654",
        "prefix": "93.175.147.0/24"
      },
      {
        "asn": "AS12654",
        "prefix": "2001:7fb:fd02::/48"
      }
    ]
  }

When referring to the file with the :option:`--json` and :option:`--input`
options, Routinator produces a JSON object that includes the validity state and
a detailed analysis of the reasoning behind the outcome of each route.

.. code-block:: text

  routinator validate --json --input beacons.json
  {
    "validated_routes": [
      {
        "route": {
          "origin_asn": "AS12654",
          "prefix": "93.175.147.0/24"
        },
        "validity": {
          "state": "invalid",
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
            ]
          }
        }
      },
      {
        "route": {
          "origin_asn": "AS12654",
          "prefix": "2001:7fb:fd02::/48"
        },
        "validity": {
          "state": "valid",
          "description": "At least one VRP Matches the Route Prefix",
          "VRPs": {
            "matched": [
              {
                "asn": "AS12654",
                "prefix": "2001:7fb:fd02::/48",
                "max_length": "48"
              }
            ],
            "unmatched_as": [
            ],
            "unmatched_length": [
            ]
          }
        }
      }
    ]
  }

Dumping Stored Data
-------------------

The :subcmd:`dump` subcommand writes the contents of all stored data to the file
system. This is primarily intended for debugging but can be used to get access
to the view of the RPKI data that Routinator currently sees. This subcommand has
only one option, :option:`--output`, which specifies the directory where the
output should be written.
   
Three directories will be created in the output directory:

rrdp
    This directory contains all the files collected via RRDP from the various 
    repositories. Each repository is stored in its own directory. The mapping
    between rpkiNotify URI and path is provided in the *repositories.json*
    file. For each repository, the files are stored in a directory structure
    based on the components of the file as rsync URI.

rsync
    This directory contains all the files collected via rsync. The files are
    stored in a directory structure based on the components of the file's rsync
    URI.

store
    This directory contains all the files used for validation. Files collected 
    via  RRDP  or rsync are copied to the store if they are correctly referenced
    by a valid manifest. This part contains one directory for each RRDP
    repository similarly structured to the *rrdp* directory and one additional
    directory *rsync* that contains files collected via rsync.

