Running Interactively
=====================

Routinator can perform :term:`RPKI <Resource Public Key Infrastructure (RPKI)>` validation
as a one-time operation and print a
:term:`validated ROA payload (VRP)` list in various formats using the :subcmd:`vrps`
subcommand and specifying the :doc:`desired format<output-formats>`. 

.. Warning:: If you have installed Routinator through the `NLnet Labs software 
             package repository <https://packages.nlnetlabs.nl>`_, the
             installation script will set up the application to run as a
             service. You should not run Routinator as a daemon and
             interactively at the same time on the same machine. 

For example, to print the :term:`VRPs <Validated ROA Payload (VRP)>` in CSV format to
standard output, run:

.. code-block:: text

   routinator vrps --format csv

To generate a file with the validated payloads in JSON format, run:

.. code-block:: text

   routinator vrps --format json --output authorisedroutes.json
   
During the validation process, logging information will be printed to standard
error. You can influence the amount of details returned with the
:option:`--verbose` and :option:`--quiet` options. To learn more about what kind
of information returned, refer to the :doc:`logging` section.

Query Options
-------------

In case you are looking for specific information in the output, Routinator
allows you to add selectors to see if a :term:`prefix <IP prefix>` or :term:`ASN
<Autonomous System Number (ASN)>` is covered or matched by a
:term:`VRP <Validated ROA Payload (VRP)>`. You can do this using the :option:`--select-asn` and
:option:`--select-prefix` options.

When using :option:`--select-asn`, you can use both ``AS64511`` and ``64511``
as the notation. With :option:`--select-prefix`, the result will include :term:`VRPs
<Validated ROA Payload (VRP)>`
regardless of their :term:`ASN <Autonomous System Number (ASN)>` and :term:`MaxLength
<Maximum Prefix Length (MaxLength)>`. Both selector flags can be combined
and used multiple times in a single query. The output for each additional
selector will be added to the results.

A validation run will be started before returning the result, making sure you
get the latest information. If you would like a result from the current cache,
you can use the :option:`--noupdate` option.

Here is an example selecting :term:`VRPs <Validated ROA Payload (VRP)>` related to a
specific :term:`ASN <Autonomous System Number (ASN)>`, produced in
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

When you query for a :term:`prefix <IP prefix>`, by default Routinator will return the exact
match, as well as less specifics. The reason is that a :term:`VRP <Validated ROA Payload
(VRP)>` of an overlapping
less specific :term:`prefix <IP prefix>` can also affect the :term:`RPKI <Resource Public
Key Infrastructure (RPKI)>` validity of a :term:`BGP <Border Gateway Protocol (BGP)>`
announcement,
depending on the :term:`Maximum Prefix Length (MaxLength)` that is set.

In some cases you may want more specifics to be displayed as well. For this
the :option:`--more-specifics` option can be used. For example, when querying
for 82.221.32.0/20:

.. code-block:: text

   routinator vrps --format json --select-prefix 82.221.32.0/20

Routinator will return the exact match and the :term:`VRP <Validated ROA Payload (VRP)>`
for the less specific /17
:term:`prefix <IP prefix>`:

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

   routinator vrps --format json --select-prefix 82.221.32.0/20 --more-specifics

You will now see that a more specific /23 :term:`prefix <IP prefix>` is returned as well:

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
         exactly matching or less specific :term:`prefix <IP prefix>`. In that case you
         will get a list of all more specific :term:`VRPs <Validated ROA Payload (VRP)>`
         covered by the :term:`prefix <IP prefix>` you
         supplied in the query.

Exclude Specific Data Types
"""""""""""""""""""""""""""

Since version 0.16.0, Routinator processes :term:`BGPsec router certificates <BGPsec
router certificate>` and
:term:`ASPA <Autonomous System Provider Authorisation (ASPA)>` objects by default. JSON
output can therefore contain :term:`router keys <BGPsec router key>` and
:term:`ASPA <Autonomous System Provider Authorisation (ASPA)>` payloads alongside route
origins. To omit a payload type from the
output, use :option:`--no-router-keys`, :option:`--no-aspas` or
:option:`--no-route-origins`, respectively.

.. deprecated:: 0.9.0
   ``--filter-asn`` and ``--filter-prefix``   
.. versionchanged:: 0.11.0
   Add the :option:`--more-specifics` option
.. versionadded:: 0.13.0
   Allow excluding specific data from the output
