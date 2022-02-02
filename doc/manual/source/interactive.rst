Running Interactively
=====================

Routinator can perform RPKI validation as a one-time operation and print a
validated ROA payload (VRP) list in various formats using the :subcmd:`vrps`
subcommand and specifying the :doc:`desired format<output-formats>`. 

.. Warning:: If you have installed Routinator through the `NLnet Labs software 
             package repository <https://packages.nlnetlabs.nl>`_, the
             installation script will set up the application to run as a
             service. You should not run Routinator as a daemon and
             interactively at the same time on the same machine. 

For example, to print the VRPs in CSV format to standard output, run:

.. code-block:: text

   routinator vrps --format csv

To generate a file with with the validated ROA payloads in JSON format, run:

.. code-block:: text

   routinator vrps --format json --output authorisedroutes.json
   
During the validation process, logging information will be printed to standard
error. You can influence the amount of details returned with the
:option:`--verbose` and :option:`--quiet` options. To learn more about what kind
of information returned, refer to the :doc:`logging` section.

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

Here is an example selecting VRPs related to a specific ASN, produced in
:term:`json` format:

.. code-block:: text

   routinator vrps --format json --select-asn 196615
   
This results in:

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

.. deprecated:: 0.9
   ``--filter-asn`` and ``--filter-prefix``   
.. versionadded:: 0.10
   Metadata in JSON format
