Routinator – *main* branch
==========================

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
Infrastructure)` Relying Party software written by `NLnet Labs
<https://nlnetlabs.nl>`_ in the Rust programming language. Routinator is a full
featured software package that runs as a service which periodically downloads
and verifies RPKI data. The built-in HTTP server offers a user interface and API
endpoints for various file formats, as well as logging, status and Prometheus
metrics.

Routinator has a built-in an RTR server allowing routers supporting route origin
validation (ROV) to connect to it to fetch verified RPKI data. Note that if you
would like to run the RTR server as a separate daemon, for example because you
want to centralise validation and distribute processed data to various locations
where routers can connect, then NLnet Labs provides :doc:`RTRTR <rtrtr:index>`.

If you run into a problem with Routinator or you have a feature request, please
`create an issue on Github <https://github.com/NLnetLabs/routinator/issues>`_.
For community support and exchanging operational experiences we provide a
`mailing list <https://lists.nlnetlabs.nl/mailman/listinfo/rpki>`_ and a
`Discord server <https://discord.gg/8dvKB5Ykhy>`_. There are also `professional
support services <https://www.nlnetlabs.nl/services/contracts/>`_ with a
service-level agreement available.

Routinator by NLnet Labs is licensed under the `BSD 3-Clause license
<https://github.com/NLnetLabs/routinator/blob/main/LICENSE>`_.

.. Tip::  To learn more about Resource Public Key Infrastructure, please refer 
          to the `RPKI Community Documentation <https://rpki.readthedocs.io/>`_.

.. toctree::
   :maxdepth: 2
   :caption: Getting Started
   :name: toc-getting-started

   installation
   installation-notes
   initialisation
   configuration
   
.. toctree::
   :maxdepth: 2
   :caption: Core
   :name: toc-core

   data-processing
   output-formats
   local-exceptions
   logging

.. toctree::
   :maxdepth: 2
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
   :caption: Interactive
   :name: toc-interactive

   interactive
   validity-checker
   dump

.. toctree::
   :maxdepth: 2
   :caption: Reference
   :name: toc-reference
   
   manual-page
   json-metrics
   prometheus-metrics
   glossary

.. history
.. authors
.. license
