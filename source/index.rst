.. _doc_routinator:

Routinator
==========

Routinator 3000 is free, open source RPKI Relying Party software written by
`NLnet Labs <https://nlnetlabs.nl>`_ in the `Rust programming language
<https://www.rust-lang.org>`_.

The application is designed to be lightweight and have great portability. This
means it can run on any Unix-like operating system, but also works on Microsoft
Windows. Due to its lean design, it can run effortlessly on minimalist hardware
such as a Raspberry Pi. Monitoring is possible through the built-in Prometheus
endpoint. It allows you to build
:ref:`beautiful dashboards <doc_routinator_monitoring_grafana>` for detailed
insights.

Routinator connects to the Trust Anchors of the five Regional Internet
Registries (RIRs) — APNIC, AFRINIC, ARIN, LACNIC and RIPE NCC — downloads all of
the certificates and ROAs in the various repositories, verifies the signatures
and makes the result available for use in the BGP workflow. It can perform RPKI
validation as a one-time operation and store the result on disk in formats such
as CSV, JSON and RPSL, or run as a service that periodically fetches and
verifies RPKI data. The data is then served via the built-in HTTP server, or
fetched from RPKI-capable routers via the RPKI-RTR protocol.

If you run into a problem with Routinator or you have a feature request, please
`create an issue on Github <https://github.com/NLnetLabs/routinator/issues>`_.
We are also happy to accept your pull requests. For general discussion and
exchanging operational experiences we provide a `mailing list
<https://lists.nlnetlabs.nl/mailman/listinfo/rpki>`_. This is also the place
where we will announce releases of the application and updates on the project.

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
   configuration
   monitoring
   manual-page

.. history
.. authors
.. license
