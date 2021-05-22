.. _doc_routinator:

Routinator – *main* branch
==========================

.. only:: html

    |docsupdated| |discord| |twitter|

    .. |docsupdated| image:: https://img.shields.io/github/last-commit/NLnetLabs/routinator-manual.svg?label=docs%20updated
                :target: https://github.com/NLnetLabs/routinator-manual/commits/main

    .. |discord| image:: https://img.shields.io/discord/818584154278199396?label=rpki%20on%20discord&logo=discord
                :target: https://discord.gg/8dvKB5Ykhy

    .. |twitter| image:: https://img.shields.io/twitter/follow/routinator3000?style=social
                :target: https://twitter.com/routinator3000/

Routinator 3000 is free, open source :abbr:`RPKI (Resource Public Key
Infrastructure)` Relying Party software written by `NLnet Labs
<https://nlnetlabs.nl>`_ in the Rust programming language. The application is
designed to be secure and have great portability. It is a lightweight
implementation that can run effortlessly on almost any operating system using 
minimalist hardware. 

Routinator connects to the Trust Anchors of the five Regional Internet
Registries (RIRs) — APNIC, AFRINIC, ARIN, LACNIC and RIPE NCC — downloads all of
the certificates and :abbr:`ROAs (Route Origin Attestations)` in the various
repositories, verifies the signatures and makes the result available for use in
your BGP workflow. 

It is a full featured software package that can perform RPKI validation as a
one-time operation and store the result on disk in formats such as CSV and JSON,
or run as a service that periodically downloads and verifies RPKI data. Routers
can connect to Routinator to fetch verified data via the :abbr:`RPKI-RTR
(RPKI-to-Router)` protocol. The built-in HTTP server offers a user interface and
endpoints for the various file formats, as well as logging, status and
Prometheus monitoring. 

If you run into a problem with Routinator or you have a feature request, please
`create an issue on Github <https://github.com/NLnetLabs/routinator/issues>`_.
We are also happy to accept your pull requests. For general discussion and
exchanging operational experiences we provide a `mailing list
<https://lists.nlnetlabs.nl/mailman/listinfo/rpki>`_ and a `Discord server
<https://discord.gg/8dvKB5Ykhy>`_. You can follow the adventures of Routinator
on `Twitter <https://twitter.com/routinator3000>`_ and listen to its favourite
songs on `Spotify
<https://open.spotify.com/user/alex.band/playlist/1DkYwN4e4tq73LGAeUykA1?si=AXNn9GkpQ4a-q5skG1yiYQ>`_.

.. Tip::  Throughout this documentation you will find references to standards
          and specific terminology. For more information, please refer to the
          `RPKI Community Documentation <https://rpki.readthedocs.io/>`_.

.. toctree::
   :maxdepth: 2
   :caption: Getting Started
   :name: toc-getting-started

   installation
   installation-notes
   initialisation
   
.. toctree::
   :maxdepth: 2
   :caption: Core
   :name: toc-core

   data-processing
   output-formats
   configuration
   local-exceptions
   logging

.. toctree::
   :maxdepth: 2
   :caption: Interactive
   :name: toc-interactive

   interactive
   validity-checker
   dump

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
   :caption: Reference
   :name: toc-reference
   
   manual-page

.. history
.. authors
.. license
