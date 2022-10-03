VRP Output Formats
==================

Routinator can perform RPKI validation as a one-time operation or run as a
daemon. In both operating modes validated ROA payloads (VRPs) can be
generated in a wide range of output formats for various use cases.

.. Tip:: In many of the output formats, the name of the trust anchor from 
         where the VRP originated is provided. This name is derived from the
         file name of the TAL, without  the *.tal* extension. If you would 
         like a different name, the *tal-label* option in the 
         :doc:`configuration file <configuration>` lets you create a mapping
         between the file name and your desired label.

.. glossary::

    csv
          The list is formatted as lines of comma-separated values of the
          following items:

            -  The prefix in slash notation, 
            -  the maximum prefix length, 
            -  the Autonomous System Number, and 
            -  the name of the trust anchor the entry is derived from. 
          
          .. code-block:: text
            
            ASN,IP Prefix,Max Length,Trust Anchor
            AS196615,2001:7fb:fd03::/48,48,ripe
            AS196615,2001:7fb:fd04::/48,48,ripe
            AS196615,93.175.147.0/24,24,ripe
          
    csvcompat
          This is the same as the *csv* format except that all fields are
          embedded in double quotes and the Autonomous System Number is given
          without the prefix *AS*. This format is pretty much identical to
          the CSV format produced by the RIPE NCC RPKI Validator.
          
          .. code-block:: text
              
              "ASN","IP Prefix","Max Length","Trust Anchor"
              "196615","2001:7fb:fd03::/48","48","ripe"
              "196615","2001:7fb:fd04::/48","48","ripe"
              "196615","93.175.147.0/24","24","ripe"
              
    csvext
          This is an extended version of the *csv* format, which was used by
          the RIPE NCC RPKI Validator 1.x. Each line contains these
          comma-separated values: 
          
            - The rsync URI of the ROA the line is taken from (or "N/A" if it
              isn't from a ROA), 
            - the Autonomous System Number, 
            - the prefix in slash notation, 
            - the maximum prefix length, and 
            - the not-before and not-after date of the validity of the ROA.
          
          .. Note:: This format is available for backwards compatibility
                    reasons only. One particular limitation is that it does 
                    not consider duplicate ROAs. Please use :term:`jsonext`
                    as a comprehensive output format.

          .. code-block:: text
            
            URI,ASN,IP Prefix,Max Length,Not Before,Not After
            rsync://rpki.ripe.net/repository/DEFAULT/73/fe2d72-c2dd-46c1-9429-e66369649411/1/49sMtcwyAuAW2lVDSQBGhOHd9og.roa,AS196615,2001:7fb:fd03::/48,48,2021-05-03 14:51:30,2022-07-01 00:00:00
            rsync://rpki.ripe.net/repository/DEFAULT/73/fe2d72-c2dd-46c1-9429-e66369649411/1/49sMtcwyAuAW2lVDSQBGhOHd9og.roa,AS196615,2001:7fb:fd04::/48,48,2021-05-03 14:51:30,2022-07-01 00:00:00
            rsync://rpki.ripe.net/repository/DEFAULT/73/fe2d72-c2dd-46c1-9429-e66369649411/1/49sMtcwyAuAW2lVDSQBGhOHd9og.roa,AS196615,93.175.147.0/24,24,2021-05-03 14:51:30,2022-07-01 00:00:00
              
    json
          The output is in JSON format. The list is placed into a member
          named *roas* which contains an array of objects with four elements
          each: 
          
            - *asn* lists the Autonomous System Number of the network
              authorised to originate a prefix,
            - *prefix* has the prefix in slash notation,
            - *maxLength* states the maximum prefix length of the announced
              route, and
            - *ta* has the trust anchor from which the authorisation was
              derived. 
          
          This format of the *roas* element is identical to that produced by
          the RIPE NCC RPKI Validator except for different naming of the
          trust anchor. 
          
          The output object also includes a member named *metadata* which
          provides additional information. Currently, this is a member
          *generated* which provides the time the list was generated as a
          Unix timestamp, and a member *generatedTime* which provides the
          same time but in the standard ISO date format.
          
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

          .. versionchanged:: 0.10.0
             Add the *metadata* member

    jsonext
          The list is placed into a JSON object with three members:

            - *roas* contains the validated route origin authorisations,
            - *routerKeys* contains the validated
              :ref:`advanced-features:bgpsec` router keys, and 
            - *metadata* contains some information about the validation run
              itself.

          All three members are always present, even if
          :ref:`advanced-features:bgpsec` has not been enabled. In this case,
          *routerKeys* will simply be empty.

          The *roas* member contains an array of objects with four elements
          each: 
          
            - *asn* lists the Autonomous System Number of the network
              authorised to originate a prefix,
            - *prefix* has the prefix in slash notation,
            - *maxLength* states the maximum prefix length of the announced
              route, and
            - *source* contains information about the source of the
              authorisation.

          The *routerKeys* member contains an array of objects with
          four elements each: 
          
            - *asn* lists the autonomous system using the router key,
            - *SKI* has the key identifier as a string of hexadecimal digits,
            - *routerPublicKey* has the actual public key as a Base 64
              encoded string, and
            - *source* contains extended information about the source of the
              key.

          This source information the same for route origins and router keys.
          It consists of an array. Each item in that array is an object
          providing details of a source. The object will have a *type* of
          *roa* if it was derived from a valid ROA object, *cer* if it was
          derived from a published router certificate, or *exception* if it
          was an assertion in a local exception file.

          For RPKI objects, *tal* provides the name of the trust anchor
          locator the object was published under, *uri* provides the rsync
          URI of the ROA or router certificate, *validity* provides the
          validity of the ROA itself, and *chainValidity* the validity
          considering the validity of the certificates along the validation
          chain.

          For  assertions from local exceptions, *path* will provide the path
          of the local exceptions file and, optionally, *comment* will
          provide the comment if given for the assertion.

          The output object also includes a member named *metadata* which
          provides additional information. Currently, this is a member
          *generated* which provides the time the list was generated as a
          Unix timestamp, and a member *generatedTime* which provides the
          same time but in the standard ISO date format.

          Please note that because of this additional information, output in
          jsonext format will be quite large.
          
          .. code-block:: json
          
              {
                "metadata": {
                  "generated": 1658818561,
                  "generatedTime": "2022-07-26T06:56:01Z"
                },
                "roas": [{
                    "asn": "AS211321",
                    "prefix": "185.49.142.0/24",
                    "maxLength": 24,
                    "source": [{
                      "type": "roa",
                      "tal": "ripe",
                      "uri": "rsync://testbed.krill.cloud/repo/local-testbed-child/0/3138352e34392e3134322e302f32342d3234203d3e20323131333231.roa",
                      "validity": {
                        "notBefore": "2022-07-25T20:47:37Z",
                        "notAfter": "2023-07-24T20:52:37Z"
                      },
                      "chainValidity": {
                        "notBefore": "2022-07-25T20:47:37Z",
                        "notAfter": "2023-02-24T12:31:01Z"
                      }
                    }]
                  }
                ],
                "routerKeys": [{
                  "asn": "AS211321",
                  "SKI": "17316903F0671229E8808BA8E8AB0105FA915A07",
                  "routerPublicKey": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAET10FMBxP6P3r6aG_ICpfsktp7X6ylJIY8Kye6zkQhNOt0y-cRzYngH8MGzY3cXNvZ64z4CpZ22gf4teybGq8ow",
                  "source": [{
                    "type": "cer",
                      "tal": "ripe",
                    "uri": "rsync://testbed.krill.cloud/repo/local-testbed-child/0/ROUTER-00033979-17316903F0671229E8808BA8E8AB0105FA915A07.cer",
                    "validity": {
                      "notBefore": "2022-07-25T20:47:37Z",
                      "notAfter": "2023-07-24T20:52:37Z"
                    },
                    "chainValidity": {
                      "notBefore": "2022-07-25T20:47:37Z",
                      "notAfter": "2023-02-24T12:31:01Z"
                    }
                  }]
                }]
              }
            
          .. versionadded:: 0.9.0
          .. versionchanged:: 0.10.0
             Add metadata
          .. versionchanged:: 0.11.0
             Add :ref:`advanced-features:bgpsec` information

    slurm
          The list is formatted as locally added assertions of a :doc:`local
          exceptions<local-exceptions>` file defined by :RFC:`8416` (also
          known as SLURM). The produced file will have empty validation
          output filters.

          .. code-block:: json

            {
              "slurmVersion": 1,
              "validationOutputFilters": {
                "prefixFilters": [ ],
                "bgpsecFilters": [ ]
              },
              "locallyAddedAssertions": {
                "prefixAssertions": [
                  {
                    "asn": 196615,
                    "prefix": "93.175.147.0/24",
                    "maxPrefixLength": 24,
                    "comment": "ripe"
                  },
                  {
                    "asn": 196615,
                    "prefix": "2001:7fb:fd03::/48",
                    "maxPrefixLength": 48,
                    "comment": "ripe"
                  },
                  {
                    "asn": 196615,
                    "prefix": "2001:7fb:fd04::/48",
                    "maxPrefixLength": 48,
                    "comment": "ripe"
                  }
                ],
                "bgpsecAssertions": [

                ]
              }
            }

          .. versionadded:: 0.11.0

    openbgpd
          Choosing this format causes Routinator to produce a *roa-set*
          configuration item for the OpenBGPD configuration.
          
          .. code-block:: text
            
            roa-set {
                2001:7fb:fd03::/48 source-as 196615
                2001:7fb:fd04::/48 source-as 196615
                93.175.147.0/24 source-as 196615
            }
            
    bird1
          Choosing this format causes Routinator to produce a ROA table
          configuration item for use with BIRD 1.6.
          
          .. code-block:: text
            
            roa 2001:7fb:fd03::/48 max 48 as 196615;
            roa 2001:7fb:fd04::/48 max 48 as 196615;
            roa 93.175.147.0/24 max 24 as 196615;

    bird2
          Choosing this format causes Routinator to produce a route table
          configuration item for BIRD 2.0 configuration.
          
          .. code-block:: text
            
            route 2001:7fb:fd03::/48 max 48 as 196615;
            route 2001:7fb:fd04::/48 max 48 as 196615;
            route 93.175.147.0/24 max 24 as 196615;

    rpsl
          This format produces a list of :abbr:`RPSL (Routing Policy
          Specification Language)` objects with the authorisation in the
          fields *route*, *origin*, and *source*. In addition, the fields
          *descr*, *mnt-by*, *created*, and *last-modified*, are present with
          more or less meaningful values.
          
          .. code-block:: text
            
            route: 93.175.147.0/24
            origin: AS196615
            descr: RPKI attestation 
            mnt-by: NA
            created: 2021-05-07T14:28:17Z
            last-modified: 2021-05-07T14:28:17Z
            source: ROA-RIPE-RPKI-ROOT
          
    summary
          This format produces a summary of the content of the RPKI
          repository. It does not take filters into account and will always
          provide numbers for the complete repository. 
          
          For each trust anchor, it will print the number of verified ROAs
          and VRPs, as well as router certificates and keys. Note that router
          keys will only be verified and included in the totals if you have
          enabled :ref:`advanced-features:bgpsec`.
                
          .. code-block:: text
          
            Summary at 2022-01-28 08:37:27.046365 UTC
            afrinic: 
                        ROAs:    3587 verified;
                        VRPs:    4545 verified,       3 unsafe,    4466 final;
                router certs:       0 verified;
                 router keys:       0 verified,       0 final.
            apnic: 
                        ROAs:   18612 verified;
                        VRPs:   85992 verified,       0 unsafe,   85711 final;
                router certs:       0 verified;
                 router keys:       0 verified,       0 final.
            arin: 
                        ROAs:   41500 verified;
                        VRPs:   50495 verified,       5 unsafe,    1812 final;
                router certs:       0 verified;
                 router keys:       0 verified,       0 final.
            lacnic: 
                        ROAs:   11744 verified;
                        VRPs:   23628 verified,       0 unsafe,   21235 final;
                router certs:       0 verified;
                 router keys:       0 verified,       0 final.
            ripe: 
                        ROAs:   27195 verified;
                        VRPs:  149164 verified,      17 unsafe,  149162 final;
                router certs:       2 verified;
                 router keys:       2 verified,       2 final.

            total: 
                        ROAs:  141922 verified;
                        VRPs:  361536 verified,      25 unsafe,  307434 final;
                router certs:       2 verified;
                 router keys:       2 verified,       2 final.

          .. versionchanged:: 0.11.0
             Reformat, sort alphabetically and add 
             :ref:`advanced-features:bgpsec` information
