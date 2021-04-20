.. _doc_routinator:

Routinator
==========

Routinator 3000 is free, open source RPKI Relying Party software written by
`NLnet Labs <https://nlnetlabs.nl>`_ in the `Rust programming language
<https://www.rust-lang.org>`_.

The application is designed to be lightweight and have great portability. This
means it can run on any Unix-like operating system, but also works on Microsoft
Windows. Due to its lean design, it can run effortlessly on minimalist hardware
such as a Raspberry Pi. 

Routinator connects to the Trust Anchors of the five Regional Internet
Registries (RIRs) — APNIC, AFRINIC, ARIN, LACNIC and RIPE NCC — downloads all of
the certificates and ROAs in the various repositories, verifies the signatures
and makes the result available for use in the BGP workflow. 

It is a full featured software package that can perform RPKI validation
as a one-time operation and store the result on disk in formats such as CSV, JSON
and RPSL, or run as a service that periodically downloads and verifies RPKI data. 
Routers can connect to Routinator to fetch verified RPKI data via the RTR protocol.
The built-in HTTP server offers a user interface and endpoints for the various file 
formats, as well as logging, status and Prometheus monitoring. 

If you run into a problem with Routinator or you have a feature request, please
`create an issue on Github <https://github.com/NLnetLabs/routinator/issues>`_.
We are also happy to accept your pull requests. For general discussion and
exchanging operational experiences we provide a `mailing list
<https://lists.nlnetlabs.nl/mailman/listinfo/rpki>`_ and a `Discord server
<https://discord.gg/8dvKB5Ykhy>`_`. 

You can follow the adventures of Routinator on `Twitter
<https://twitter.com/routinator3000>`_ and listen to its favourite songs on
`Spotify
<https://open.spotify.com/user/alex.band/playlist/1DkYwN4e4tq73LGAeUykA1?si=
AXNn9GkpQ4a-q5skG1yiYQ>`_.

.. toctree::
   :maxdepth: 2
   :name: toc-routinator

   installation
   installation-notes
   initialisation
   interactive
   daemon
   user-interface
   monitoring
   configuration
   manual-page

.. history
.. authors
.. license
