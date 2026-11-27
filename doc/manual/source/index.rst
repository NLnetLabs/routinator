Routinator |version|
====================

Routinator is an open-source :term:`RPKI <Resource Public Key Infrastructure (RPKI)>`
validator developed by NLnet Labs. It
fetches and validates objects published in the :term:`Resource Public Key
Infrastructure (RPKI)`. Its built-in :term:`RPKI-to-Router (RTR) <RPKI-to-Router
(RPKI-RTR)>` server supplies
routers with the resulting data. Routers can use this data to check the
origin of a :term:`BGP <Border Gateway Protocol (BGP)>` announcement or, with :doc:`ASPA
<aspa>` support, to verify
its :term:`AS path <AS path (AS_PATH)>`. Your routing policy determines how those checks
affect route
selection.

Run Routinator
--------------

Start with :doc:`installation` for system requirements and installation
options. To keep validation data up to date and serve it to your routers,
follow :doc:`daemon` and :doc:`rtr-service`. For a one-off validation run
or to export the results from the command line, see :doc:`interactive`.

Inspect validation data
-----------------------

To check whether an :term:`AS <Autonomous System (AS)>` is authorised to originate a
particular :term:`prefix <IP prefix>`, use
the :doc:`validity checker <validity-checker>`. The :doc:`user interface
<user-interface>` lets you explore the data in a browser, and the
:doc:`HTTP API <api-endpoints>` gives applications access to the results.
See :doc:`data-processing` for how Routinator builds its validated data set.

Monitor a running instance
--------------------------

Use :doc:`monitoring` to check when validation last completed, inspect
:term:`repository` status and collect Prometheus metrics. See :doc:`logging` to
diagnose problems fetching or validating :term:`repository` data.

Further information and support
-------------------------------

The `RPKI documentation <https://rpki.readthedocs.io/>`_ introduces the
technology and its use in routing. For questions about running Routinator,
visit the `NLnet Labs community forum <https://community.nlnetlabs.nl/>`_.
NLnet Labs also offers `professional support
<https://www.nlnetlabs.nl/services/contracts/>`_.

.. toctree::
   :maxdepth: 2
   :hidden:
   :caption: Getting Started
   :name: toc-getting-started

   installation
   building
   configuration

.. toctree::
   :maxdepth: 2
   :hidden:
   :caption: Core
   :name: toc-core

   data-processing
   aspa
   output-formats
   local-exceptions
   logging

.. toctree::
   :maxdepth: 2
   :hidden:
   :caption: Service
   :name: toc-service

   daemon
   rtr-service
   http-service
   user-interface
   api-endpoints
   monitoring

.. toctree::
   :maxdepth: 2
   :hidden:
   :caption: Interactive
   :name: toc-interactive

   interactive
   validity-checker
   dump

.. toctree::
   :maxdepth: 2
   :hidden:
   :caption: Reference
   :name: toc-reference

   manual-page
   threat-model
   json-metrics
   prometheus-metrics
   unsafe-vrps
   advanced-features
   glossary

.. history
.. authors
.. license
