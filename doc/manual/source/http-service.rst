HTTP Service
============

In addition to the various :doc:`VRP output formats<output-formats>`,
Routinator's HTTP server also provides a :doc:`user
interface<user-interface>`, an :doc:`API<api-endpoints>`,
:doc:`monitoring<monitoring>` and :doc:`logging<logging>` endpoints. 

The HTTP server is not enabled by default for security reasons, nor does it
have a default host or port. Routinator natively supports `TLS Transport`_,
but the endpoints are set up in such a way that it's easy to configure a
:ref:`reverse proxy <http-service:using a reverse proxy>` as well.

In order to start the HTTP server at 192.0.2.13 and 2001:0DB8::13 on port
8323, run:

.. code-block:: text

   routinator server --http 192.0.2.13:8323 --http [2001:0DB8::13]:8323

After fetching and verifying all RPKI data, paths are available for each
:doc:`VRP output format <output-formats>`. For example, at the ``/json`` path
you can fetch a list of all VRPs in JSON format.

.. code-block:: text

   curl http://192.0.2.13:8323/json

Query Parameters
----------------

These paths accept selector expressions to limit the VRPs returned in the
form of a query parameter. You can use ``select-asn`` to select ASNs and
``select-prefix`` to select prefixes. These expressions can be repeated
multiple times. The output for each additional parameter will be added to the
results.

For example, to only show the VRPs in JSON format authorising AS196615, use:

.. code-block:: text

   curl http://192.0.2.13:8323/json?select-asn=196615

This will produce the following output:

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

When you query for a prefix, by default Routinator will return the exact
match, as well as less specific prefixes. In case you also want more more
specifics to be displayed, the ``more-specifics`` query string can be used.

For example, when querying for 93.175.144.0/20 and requesting more specific
prefixes, we'll get all of the IPv4 VRPs for the RIPE NCC RIS anchors and 
beacons in this range:

.. code-block:: text

   curl http://192.0.2.13:8323/json?select-prefix=93.175.144.0/20&include=more-specifics

This will produce the following output:

.. code-block:: json

   {
      "metadata": {
         "generated": 1644252691,
         "generatedTime": "2022-02-07T16:51:31Z"
      },
      "roas": [
         { "asn": "AS12654", "prefix": "93.175.146.0/24", "maxLength": 24, "ta": "ripe" },
         { "asn": "AS196615", "prefix": "93.175.147.0/24", "maxLength": 24, "ta": "ripe" },
         { "asn": "AS12654", "prefix": "93.175.148.0/24", "maxLength": 24, "ta": "ripe" },
         { "asn": "AS12654", "prefix": "93.175.149.0/24", "maxLength": 24, "ta": "ripe" },
         { "asn": "AS12654", "prefix": "93.175.150.0/24", "maxLength": 24, "ta": "ripe" },
         { "asn": "AS12654", "prefix": "93.175.151.0/24", "maxLength": 24, "ta": "ripe" },
         { "asn": "AS12654", "prefix": "93.175.152.0/24", "maxLength": 24, "ta": "ripe" },
         { "asn": "AS12654", "prefix": "93.175.153.0/24", "maxLength": 24, "ta": "ripe" },
         { "asn": "AS12859", "prefix": "93.175.159.0/24", "maxLength": 24, "ta": "ripe" },
         { "asn": "AS201965", "prefix": "93.175.159.0/24", "maxLength": 24, "ta": "ripe" }
      ]
   }

.. versionadded:: 0.11
   ``more-specifics`` query parameter

TLS Transport
-------------

Routinator offers native TLS suppport for both HTTP and :doc:`RTR
connections<rtr-service>`. In this example we'll start Routinator's HTTPS
server listening on the IP addresses 192.0.2.13 and 2001:0DB8::13 and use
port 8324.

First, indidate that you want a TLS connection with the :option:`--http-tls`
option. Then use the :option:`--http-tls-cert` option to specify the path to
a file containing the server certificates to be used. This file has to
contain one or more certificates encoded in PEM format. Lastly, use the
:option:`--http-tls-key` option to specify the path to a file containing the
private key to be used for HTTPS connections. The file has to contain exactly
one private key encoded in PEM format:

.. code-block:: text

   routinator server --http-tls 192.0.2.13:8324 \
                     --http-tls [2001:0DB8::13]:8324 \
                     --http-tls-cert "/path/to/http-tls.crt" \
                     --http-tls-key "/path/to/http-tls.key"

Using a Reverse Proxy
---------------------

Though TLS is natively supported, it may be more convenient to set up a
reverse proxy to serve HTTPS data. This way you'll be using a production
grade web server that for example allows automation of certificate renewal.

For convenience, all the files and folders for the :doc:`user
interface<user-interface>` are hosted under the ``/ui`` path and the
:doc:`API endpoints<api-endpoints>` are under ``/api``. For example, this
allows you to just expose the UI and not any of the other paths, such as
those serving the various :doc:`VRP output formats<output-formats>`.

In this example we'll use NGINX, but other web servers will allow a similar,
simple configuration. To only expose the user interface, this is what your
configuration needs at a minimum when running it on the same server as
Routinator runs on, using port 8323.

Using the ``=`` modifier, the first entry only forwards if the path is
*exactly* ``/`` so that paths not explicitely mentioned, such as ``/json``,
are not forwarded. For more information, please refer to the `NGINX
documentation <https://nginx.org/en/docs/http/server_names.html>`_.

.. code-block:: text

    location = / {
      proxy_pass http://127.0.0.1:8323/;
    }
    location /ui {
      proxy_pass http://127.0.0.1:8323/ui;
    }
    location /api {
      proxy_pass http://127.0.0.1:8323/api;
    } 

