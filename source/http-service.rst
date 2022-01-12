HTTP Service
============

In addition to the various :doc:`VRP output formats<output-formats>`,
Routinator's HTTP server also provides a :doc:`user interface<user-interface>`,
an :doc:`API<api-endpoints>`, :doc:`monitoring<monitoring>` and
:doc:`logging<logging>` endpoints. 

The HTTP server is not enabled by default for security reasons, nor does it have
a default host or port. This service is intended to run on your internal network
and doesn't offer HTTPS natively. If this is a requirement, you can for example
run Routinator behind a :ref:`reverse proxy <user-interface:reverse proxy with
nginx>`.

In order to start the HTTP server at 192.0.2.13 and 2001:0DB8::13 on port 8323,
run:

.. code-block:: text

   routinator server --http 192.0.2.13:8323 --http [2001:0DB8::13]:8323

After fetching and verifying all RPKI data, paths are available for each
:doc:`VRP output format <output-formats>`. For example, at the :command:`/csv`
path you can fetch a list of all VRPs in CSV format.

.. code-block:: text

   curl http://192.0.2.13:8323/csv

These paths accept selector expressions to limit the VRPs returned in the form
of a query string. You can use ``select-asn`` to select ASNs and
``select-prefix`` to select prefixes. These expressions can be repeated multiple
times. 

For example, to only show the VRPs in JSON format authorising AS196615, use:

.. code-block:: text

   curl http://192.0.2.13:8323/json?select-asn=196615

This will produce the following output:

.. code-block:: json

   {
      "metadata": {
        "generated": 1626853335,
        "generatedTime": "2021-07-21T07:42:15Z"
     },
      "roas": [
         { "asn": "AS196615", "prefix": "2001:7fb:fd03::/48", "maxLength": 48, "ta": "ripe" },
         { "asn": "AS196615", "prefix": "2001:7fb:fd04::/48", "maxLength": 48, "ta": "ripe" },
         { "asn": "AS196615", "prefix": "93.175.147.0/24", "maxLength": 24, "ta": "ripe" }
      ]
    }