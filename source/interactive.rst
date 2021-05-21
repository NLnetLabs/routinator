.. _doc_routinator_interactive:

Running Interactively
=====================

.. deprecated:: 0.9
   ``--filter-asn`` and ``--filter-prefix``

Routinator can perform RPKI validation as a one-time operation and print a
validated ROA payload (VRP) list in various formats using the :subcmd:`vrps`
subcommand and specifying the :ref:`desired format
<doc_routinator_output_formats>`. 

For example, to print the VRPs in CSV format to standard output, run:

.. code-block:: text

   routinator vrps --format csv

To generate a file with with the validated ROA payloads in JSON format, run:

.. code-block:: text

   routinator vrps --format json --output authorisedroutes.json
   
During the validation process, logging information will be printed to standard
error. You can influence the amount of details returned with the
:option:`--verbose` and :option:`--quiet` options. To learn more about what kind
of information returned, refer to the :ref:`Logging <doc_routinator_logging>`
section.

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
you can use the :option:`--noupdate` option.

Here is an example selecting VRPs related to a specific ASN, produced in JSON
format:

.. code-block:: text

   routinator vrps --format json --select-asn 196615
   
This results in:

.. code-block:: json
   
    {
      "roas": [
        { "asn": "AS196615", "prefix": "2001:7fb:fd03::/48", "maxLength": 48, "ta": "ripe" },
        { "asn": "AS196615", "prefix": "2001:7fb:fd04::/48", "maxLength": 48, "ta": "ripe" },
        { "asn": "AS196615", "prefix": "93.175.147.0/24", "maxLength": 24, "ta": "ripe" }
      ]
    }
