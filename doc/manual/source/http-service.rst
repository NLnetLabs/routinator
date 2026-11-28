HTTP Service
============

Routinator has a built-in HTTP server, which can be started with the
:option:`--http` command line option or the :term:`http-listen` option in the
configuration file. Routinator natively supports `TLS Transport`_ and the
endpoints are set up in such a way that it's easy to configure a
:ref:`reverse proxy <http-service:using a reverse proxy>` as well.

In addition to the various :doc:`VRP output formats<output-formats>`,
Routinator's HTTP server also provides a :doc:`user
interface<user-interface>`, an :doc:`API<api-endpoints>`,
:doc:`monitoring<monitoring>` and :doc:`logging<logging>` endpoints. 

After fetching and verifying all :term:`RPKI <Resource Public Key Infrastructure (RPKI)>`
data for the first time, paths are
available for each :doc:`VRP output format <output-formats>`. For example, at
the ``/json`` path you can fetch a list of all :term:`VRPs <Validated ROA Payload (VRP)>`
in JSON format.

.. code-block:: text

   curl http://192.0.2.13:8323/json

Query Parameters
----------------

Payload output endpoints such as ``/json`` accept the query parameters
``select-asn`` and ``select-prefix`` to filter results by :term:`ASN <Autonomous System
Number (ASN)>` or :term:`prefix <IP prefix>`.
Results include payloads matching any of the supplied selectors.

For example, to only show the VRPs in JSON format
authorising AS196615, use:

.. code-block:: text

   curl 'http://192.0.2.13:8323/json?select-asn=196615'

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

The query parameter ``exclude`` can be used to exclude certain payload types
from the response. The values ``routeOrigins``, ``routerKeys``, and ``aspas``
disable inclusion of route origins, :term:`router keys <BGPsec router key>`, and
:term:`ASPAs <Autonomous System Provider Authorisation (ASPA)>`, respectively. The
values can either be given in separate ``exclude`` parameters or included in
one separated by commas.

.. versionadded:: 0.13.0
   Allow excluding specific data from the output

More Specific Prefixes
""""""""""""""""""""""

When you query for a prefix, by default Routinator will return the exact
match, as well as less specifics. The reason is that a VRP of an overlapping
less specific prefix can also affect the RPKI validity of a :term:`BGP <Border Gateway Protocol (BGP)>`
announcement,
depending on the :term:`Maximum Prefix Length (MaxLength)` that is set.

For example, to query for 82.221.32.0/20:

.. code-block:: text

   curl 'http://192.0.2.13:8323/json?select-prefix=82.221.32.0/20'

Routinator will return the exact match and the VRP
for the less specific /17
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

To include more specific prefixes, add ``include=more-specifics``:

.. code-block:: text

   curl 'http://192.0.2.13:8323/json?select-prefix=82.221.32.0/20&include=more-specifics'

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

.. Tip:: The ``include=more-specifics`` option will also work if there is no
         exactly matching or less specific prefix. In that case you
         will get a list of all more specific VRPs
         covered by the prefix you
         supplied in the query.

.. versionchanged:: 0.11.0
   Support for ``include=more-specifics``

TLS Transport
-------------

Routinator offers native :term:`TLS <Transport Layer Security (TLS)>` support for both
HTTP and :doc:`RTR
connections<rtr-service>`. In this example we'll start Routinator's HTTPS
server listening on the IP addresses 192.0.2.13 and 2001:0DB8::13 and use
port 8324.

First, indicate that you want a TLS connection
with the :option:`--http-tls`
option. Then use the :option:`--http-tls-cert` option to specify the path to
a file containing the server certificates to be used. This file has to
contain one or more certificates encoded in :term:`PEM format <PEM encoding>`. Lastly, use the
:option:`--http-tls-key` option to specify the path to a file containing the
private key to be used for HTTPS connections. The file has to contain exactly
one private key encoded in PEM format:

.. code-block:: text

   routinator server --http-tls 192.0.2.13:8324 \
                     --http-tls [2001:0DB8::13]:8324 \
                     --http-tls-cert "/path/to/http-tls.crt" \
                     --http-tls-key "/path/to/http-tls.key"

.. versionadded:: 0.11.0

Using a Reverse Proxy
---------------------

A reverse proxy can manage HTTPS certificates and forward requests to
Routinator's HTTP service. In the examples below, Routinator listens on
``127.0.0.1:8323`` and the proxy runs on the same host.

The examples make the :doc:`user interface <user-interface>` available at
``/ui/`` and forward requests under ``/api/``. This includes
``/api/v1/status``, which provides monitoring data, and ``/api/v1/origins/``,
which serves the same JSON data as ``/json``. Clients can therefore retrieve
the data set through the API even though these rules do not forward the
top-level ``/json`` path.

NGINX
"""""

Add these locations to the HTTPS server block. The ``=`` modifier matches
the root path exactly, allowing Routinator to redirect that request to
``/ui/``. See the `NGINX location documentation
<https://nginx.org/en/docs/http/ngx_http_core_module.html#location>`_.

.. code-block:: nginx

    location = / {
      proxy_pass http://127.0.0.1:8323/;
    }
    location /ui {
      proxy_pass http://127.0.0.1:8323/ui;
    }
    location /api {
      proxy_pass http://127.0.0.1:8323/api;
    } 

Apache
""""""

In an Apache HTTPS virtual host, redirect the root path to the UI and
forward requests for the UI and API to Routinator.

.. code-block:: apache

    <VirtualHost *:443>
       ProxyPreserveHost On
       AllowEncodedSlashes On

       <LocationMatch "^/$">
           Redirect / /ui
       </LocationMatch>

       ProxyPass /api http://127.0.0.1:8323/api
       ProxyPassReverse /api http://127.0.0.1:8323/api

       ProxyPass /ui http://127.0.0.1:8323/ui
       ProxyPassReverse /ui http://127.0.0.1:8323/ui
    </VirtualHost>

Caddy
"""""

Replace ``rpki.example.net`` with the public hostname pointing to your
proxy. Caddy can obtain and renew the certificate automatically. The
path matcher forwards requests for the root, UI and API to Routinator.
The final ``handle`` block returns HTTP 404 for any other path.

.. code-block:: text

    rpki.example.net {
        @routinator path / /ui /ui/* /api/*
        handle @routinator {
            reverse_proxy 127.0.0.1:8323
        }
        handle {
            respond 404
        }
    }

See `Caddy's automatic HTTPS documentation
<https://caddyserver.com/docs/automatic-https>`_ for certificate issuance
requirements.
