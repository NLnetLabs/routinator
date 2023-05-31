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

If you have enabled :ref:`advanced-features:bgpsec` and/or
:ref:`advanced-features:aspa` validation, in some output formats the amount
of data can be quite overwhelming. You can exclude specific data types for the
output with the :option:`--no-route-origins`, :option:`--no-router-keys` and
the :option:`--noaspas` options.

.. versionchanged:: 0.13.0
   Allow excluding specific data from the output.

Query Options
-------------

In case you are looking for specific information in the output, Routinator
allows you to add selectors to see if a prefix or ASN is covered or matched by a
VRP. You can do this using the :option:`--select-asn` and
:option:`--select-prefix` options.

When using :option:`--select-asn`, you can use both ``AS64511`` and ``64511``
as the notation. With :option:`--select-prefix`, the result will include VRPs
regardless of their ASN and MaxLength. Both selector flags can be combined
and used multiple times in a single query. The output for each additional
selector will be added to the results.

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

More Specific Prefixes
""""""""""""""""""""""

When you query for a prefix, by default Routinator will return the exact
match, as well as less specifics. The reason is that a VRP of an overlapping
less specific prefix can also affect the RPKI validity of a BGP announcement,
depending on the :term:`Maximum Prefix Length (MaxLength)` that is set.

In some cases you may want more specifics to be displayed as well. For this
the :option:`--more-specifics` option can be used. For example, when querying
for 82.221.32.0/20:

.. code-block:: text

   routinator vrps --format json --select-asn 82.221.32.0/20

Routinator will return the exact match and the VRP for the less specific /17
prefix:

.. code-block:: json

   {
      "metadata": {
         "generated": 1644266267,
         "generatedTime": "2022-02-07T20:37:47Z"
      },
      "roas": [
         { "asn": "AS30818", "prefix": "82.221.32.0/20", "maxLength": 20, "ta": "ripe" },
         { "asn": "AS44515", "prefix": "82.221.0.0/17", "maxLength": 17, "ta": "ripe" }
      ]
   }

When including the :option:`--more-specifics` option in the same query:

.. code-block:: text

   routinator vrps --format json --select-asn 82.221.32.0/20 --more-specifics

You will now see that a more specific /23 prefix is returned as well:

.. code-block:: json

   {
      "metadata": {
         "generated": 1644266267,
         "generatedTime": "2022-02-07T20:37:47Z"
      },
      "roas": [
         { "asn": "AS44515", "prefix": "82.221.46.0/23", "maxLength": 23, "ta": "ripe" },
         { "asn": "AS30818", "prefix": "82.221.32.0/20", "maxLength": 20, "ta": "ripe" },
         { "asn": "AS44515", "prefix": "82.221.0.0/17", "maxLength": 17, "ta": "ripe" }
      ]
   }

.. Tip:: The :option:`--more-specifics` option will also work if there is no
         exactly matching or less specific prefix. In that case you
         will get a list of all more specific VRPs covered by the prefix you
         supplied in the query.

Exclude Specific Data Types
"""""""""""""""""""""""""""

If you have enabled :ref:`advanced-features:bgpsec` and/or
:ref:`advanced-features:aspa` validation, in some output formats the amount of
data can be quite overwhelming. You can exclude specific payload types with
the :option:`--no-route-origins`, :option:`--no-router-keys` and
:option:`--noaspas` options to disable inclusion of route origins, router
keys, and ASPAs, respectively.

.. deprecated:: 0.9.0
   ``--filter-asn`` and ``--filter-prefix``   
.. versionchanged:: 0.11.0
   Add the :option:`--more-specifics` option
.. versionadded:: 0.13.0
   Allow excluding specific data from the output
