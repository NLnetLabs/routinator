.. _doc_routinator_validity_checker:

Validity Checker
================

You can check the RPKI origin validation status of one or more BGP announcements
using the :subcmd:`validate` subcommand and by supplying the ASN and prefix. A
validation run will be started before returning the result, making sure you get
the latest information. If you would like a result from the current cache, you
can use the :option:`--noupdate` option:

.. code-block:: text

   routinator validate --asn 12654 --prefix 93.175.147.0/24

This will simply return the RPKI validity state:
   
.. code-block:: text
   
   Invalid

You can also add the :option:`--json` option:

.. code-block:: text

   routinator validate --json --asn 12654 --prefix 93.175.147.0/24
   
This will produce a detailed analysis of the reasoning behind the validation
outcome is printed in JSON format. In case of an Invalid state, whether this
because the announcement is originated by an unauthorised AS, or if the prefix
is more specific than the maximum prefix length allows. Lastly, a complete list
of VRPs that caused the result is included:
   
.. code-block:: json   
   
   {
     "validated_route": {
      "route": {
        "origin_asn": "AS12654",
        "prefix": "93.175.147.0/24"
      },
      "validity": {
        "state": "Invalid",
        "reason": "as",
        "description": "At least one VRP Covers the Route Prefix, but no 
         VRP ASN matches the route origin ASN",
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
-------------------------

.. versionadded:: 0.9

Routinator can also read input to validate from a file using the
:option:`--input` option. If the file is given as a single dash, input is
read from standard input. You can also save the results to a file using the
:option:`--output` option.

You can provide a simple plain text file with the routes you would like to have
verified by Routinator. The input file should have one route announcement per
line, provided as a prefix followed by an ASCII-art arrow ``=>`` surrounded by
white space and followed by the AS Number of the originating Autonomous System.

For example, let's provide Routinator with this file, saved as
:file:`beacons.txt`:

.. code-block:: text

   93.175.147.0/24 => 12654
   2001:7fb:fd02::/48 => 12654

Now we refer to the file with the :option:`--input` option:

.. code-block:: text

   routinator validate --input beacons.txt 
   
Routinator provides the RPKI validity state in the output:   
   
.. code-block:: text   
   
   93.175.147.0/24 => AS12654: invalid
   2001:7fb:fd02::/48 => AS12654: valid

With the :option:`--json` option you can provide a file in JSON format. It
should consist of a single object with one member *routes*  which contains an
array of objects. Each object describes one route announcement through its
*prefix* and *asn* members which contain a prefix and originating AS number as
strings, respectively.

For example, let's provide Routinator with this :file:`beacons.json` file:

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

Then refer to the file with the :option:`--json` and :option:`--input`
options:

.. code-block:: text

  routinator validate --json --input beacons.json
  
Routinator produces a JSON object that includes the validity state and a
detailed analysis of the reasoning behind the outcome of each route:  
  
.. code-block:: json  
  
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
          "description": "At least one VRP Covers the Route Prefix, but no
           VRP ASN matches the route origin ASN",
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