Routinator
==========

.. only:: html

    |docsupdated| |license| |discord| |twitter|
    
    .. |docsupdated| image:: https://img.shields.io/github/last-commit/NLnetLabs/routinator-manual.svg?label=docs%20updated
                :target: https://github.com/NLnetLabs/routinator-manual/commits/main

    .. |license| image:: https://img.shields.io/github/license/nlnetlabs/routinator
                :target: https://github.com/NLnetLabs/routinator/blob/main/LICENSE

    .. |discord| image:: https://img.shields.io/discord/818584154278199396?label=rpki%20on%20discord&logo=discord
                :target: https://discord.gg/8dvKB5Ykhy

    .. |twitter| image:: https://img.shields.io/twitter/follow/routinator3000?style=social
                :target: https://twitter.com/routinator3000/

Routinator 3000 is free, open source :abbr:`RPKI (Resource Public Key
Infrastructure)` Relying Party software made by `NLnet Labs
<https://nlnetlabs.nl>`_. The software is written in Rust, a programming
language designed for performance and memory safety.

Full-featured, lightweight and secure
   Routinator runs as a service and periodically downloads and verifies RPKI
   data. The built-in HTTPS server offers a user interface, API endpoints for
   various file formats, as well as logging, status and Prometheus metrics.

Flexible RPKI-to-Router (RTR) support
   Routinator has a built-in an RTR server to let routers fetch verified
   RPKI data. You can also run RTR as a separate daemon using our RPKI data
   proxy :doc:`RTRTR <rtrtr:index>`, letting you centralise validation and
   securely distribute processed data to various locations.

Open source with community and professional support
   We provide a `mailing list
   <https://lists.nlnetlabs.nl/mailman/listinfo/rpki>`_ and `Discord server
   <https://discord.gg/8dvKB5Ykhy>`_  for community support and to exchange
   operational experiences. NLnet Labs also offers `professional support
   services <https://www.nlnetlabs.nl/services/contracts/>`_ with a
   service-level agreement. Routinator is liberally licensed under the `BSD
   3-Clause license
   <https://github.com/NLnetLabs/routinator/blob/main/LICENSE>`_.

.. toctree::
   :maxdepth: 2
   :hidden:
   :caption: Getting Started
   :name: toc-getting-started

   installation
   installation-notes
   initialisation
   configuration
   
.. toctree::
   :maxdepth: 2
   :hidden:
   :caption: Core
   :name: toc-core

   data-processing
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
   json-metrics
   prometheus-metrics
   glossary

.. history
.. authors
.. license
