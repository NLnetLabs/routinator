Routinator |version|
====================

Routinator 3000 is free, open-source Relying Party software for Resource
Public Key Infrastructure (RPKI). Routinator is developed by `NLnet Labs
<https://nlnetlabs.nl>`_ since 2017. To learn more about RPKI, please refer
to the `technology documentation <https://rpki.readthedocs.io>`_.

Lightweight and portable
   Routinator has minimal system requirements and it can run on almost any
   hardware and platform, with packages available for most. You can also
   easily run with Docker or Cargo, the Rust package manager.

Full-featured and secure
   Routinator runs as a service that periodically downloads and verifies RPKI
   data. The built-in HTTPS server offers a user interface, API endpoints for
   various file formats, as well as logging, status and Prometheus metrics.

Flexible RPKI-to-Router (RTR) support
   Routinator has a built-in RTR server to let routers fetch verified RPKI
   data. You can also run RTR as a separate daemon using our RPKI data proxy
   :doc:`RTRTR <rtrtr:index>`, letting you centralise validation and securely
   distribute processed data to various locations.

Open-source with professional support services
   NLnet Labs offers `professional support and consultancy services
   <https://www.nlnetlabs.nl/services/contracts/>`_ with a service-level
   agreement. Community support is available on `Discord
   <https://discord.gg/8dvKB5Ykhy>`_ and our `mailing list
   <https://lists.nlnetlabs.nl/mailman/listinfo/rpki>`_. Routinator is
   liberally licensed under the `BSD 3-Clause license
   <https://github.com/NLnetLabs/routinator/blob/main/LICENSE>`_.

   .. only:: html

      |discord| |mastodon|
      
      .. |discord| image:: https://img.shields.io/discord/818584154278199396   
         :alt: Discord
         :target: https://discord.gg/8dvKB5Ykhy

      .. |mastodon| image:: https://img.shields.io/mastodon/follow/114692612288811644?domain=social.nlnetlabs.nl&style=social
         :alt: Mastodon
         :target: https://social.nlnetlabs.nl/@nlnetlabs

|

.. image:: img/routinator_badge.svg
   :width: 60%
   :align: center
   :alt: Routinator 3000

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
