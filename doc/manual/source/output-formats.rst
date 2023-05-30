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
          The list is placed into a JSON object with up to four members:

            - *roas* contains the validated route origin authorisations, 
            - *routerKeys* contains the validated
              :ref:`advanced-features:bgpsec` router keys,
            - *aspas* contains the validated :ref:`advanced-features:aspa` 
              payload, and
            - *metadata* contains some information about the validation run 
              itself. 
              
          Of the first three, only those members are present that have not 
          been disabled or excluded. 
          
          The *roas* member contains an array of objects with four elements 
          each:
          
            - *asn* lists the Autonomous System Number of the network
              authorised to originate a prefix,
            - *prefix* has the prefix in slash notation,
            - *maxLength* states the maximum prefix length of the announced
              route, and
            - *ta* has the trust anchor from which the authorisation was
              derived. 
          
          The *routerKeys* member contains an array of objects with four 
          elements each: 
          
            - *asn* contains the autonomous system using the router key,
            - *SKI* lists the key identifier as a string of hexadecimal 
              digits,
            - *routerPublicKey* contains the actual public key as a Base 64 
              encoded string, and 
            - *ta* has the trust anchor from which the authorisation was
              derived.

          The *aspa* member contains an array of objects with four members 
          each: 
          
            - *customer* contains the customer ASN,
            - *afi* lists the address family as either "ipv4" or "ipv6",
            - *providers* contains the provider ASN set as an array, and
            - *ta* has the trust anchor from which the authorisation was
              derived.
          
          The output object also includes a member named *metadata* which
          provides additional information. Currently, this is a member
          *generated* which provides the time the list was generated as a
          Unix timestamp, and a member *generatedTime* which provides the
          same time but in the standard ISO date format.
          
          .. code-block:: json
            
            {
              "metadata": {
                "generated": 1685455841,
                "generatedTime": "2023-05-30T14:10:41Z"
              },
              "roas": [{
                "asn": "AS196615",
                "prefix": "93.175.147.0/24",
                "maxLength": 24,
                "ta": "ripe"
                }
              ],
              "routerKeys": [{
                "asn": "AS211321",
                "SKI": "17316903F0671229E8808BA8E8AB0105FA915A07",
                "routerPublicKey": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAET10FMBxP6P3r6aG_ICpfsktp7X6ylJIY8Kye6zkQhNOt0y-cRzYngH8MGzY3cXNvZ64z4CpZ22gf4teybGq8ow",
                "ta": "ripe"
              }],
              "aspas": [{
                "customer": "AS64496",
                "afi": "ipv6",
                "providers": ["AS64499", "AS64511", "AS65551"],
                "ta": "ripe"
              }]
            }

          .. versionchanged:: 0.10.0
             Add the *metadata* member
          .. versionchanged:: 0.13.0
             Add the *routerKeys* and *aspas* members

    jsonext
          The list is placed into a JSON object with up to four members:

            - *roas* contains the validated route origin authorisations,
            - *routerKeys* contains the validated
              :ref:`advanced-features:bgpsec` router keys,
            - *aspas* contains the validated :ref:`advanced-features:aspa` 
              objects, and 
            - *metadata* contains some information about the validation run
              itself.

          Of the first three, only those members are present that have not 
          been disabled or excluded.

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

          The *aspas* member contains an array of objects with
          four elements each: 
          
            - *customer* contains the customer ASN,
            - *afi* specifies the address family as either "ipv4" or "ipv6",
            - *providers* contains the provider ASN set as an array, and
            - *source* contains information about the source of the
              authorisation.

          This source information the same for route origins, router keys and
          aspas. It consists of an array. Each item in that array is an
          object providing details of a source. The object will have a *type*
          of *roa* if it was derived from a valid ROA object, *cer* if it was
          derived from a published router certificate, *aspa* if it was
          derived from an ASPA object, or *exception* if it was an assertion
          in a local exception file.

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
                }],
                "aspas": [{
                  "customer": "AS64496",
                  "afi": "ipv6",
                  "providers": ["AS64499", "AS64511", "AS65551"],
                  "source": [{
                      "type": "aspa",
                      "uri": "rsync://acmecorp.example.net/0/AS64496.asa",
                      "tal": "ripe",
                      "validity": {
                          "notBefore": "2023-04-13T07:21:24Z",
                          "notAfter": "2024-04-11T07:26:24Z"
                      },
                      "chainValidity": {
                          "notBefore": "2023-04-18T14:32:13Z",
                          "notAfter": "2024-04-11T07:26:24Z"
                        }
                    }]
                }]
              }
            
          .. versionadded:: 0.9.0
          .. versionchanged:: 0.10.0
             Add metadata
          .. versionchanged:: 0.11.0
             Add :ref:`advanced-features:bgpsec` information
          .. versionchanged:: 0.13.0
             Add :ref:`advanced-features:aspa` information
          .. versionchanged:: 0.13.0
             Only include members that have not been disabled or excluded

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
          and VRPs, router certificates and keys, as well as ASPAs. Note that
          router keys and ASPAs will only be included in the totals if you
          have enabled :ref:`advanced-features:bgpsec` and
          :ref:`advanced-features:aspa`, respectively.
                
          .. code-block:: text
          
            Summary at 2023-05-30 16:22:27.060940 UTC
            afrinic: 
                        ROAs:    4896 verified;
                        VRPs:    6248 verified,    5956 final;
                router certs:       0 verified;
                 router keys:       0 verified,       0 final.
                       ASPAs:       0 verified,       0 final.
            apnic: 
                        ROAs:   25231 verified;
                        VRPs:  109978 verified,  109717 final;
                router certs:       0 verified;
                 router keys:       0 verified,       0 final.
                       ASPAs:       2 verified,       2 final.
            arin: 
                        ROAs:   63188 verified;
                        VRPs:   78064 verified,   76941 final;
                router certs:       1 verified;
                 router keys:       1 verified,       1 final.
                       ASPAs:       7 verified,       7 final.
            lacnic: 
                        ROAs:   18036 verified;
                        VRPs:   32565 verified,   30929 final;
                router certs:       0 verified;
                 router keys:       0 verified,       0 final.
                       ASPAs:       0 verified,       0 final.
            ripe: 
                        ROAs:   39081 verified;
                        VRPs:  211048 verified,  211043 final;
                router certs:       2 verified;
                 router keys:       2 verified,       2 final.
                       ASPAs:      57 verified,      57 final.
            total: 
                        ROAs:  150432 verified;
                        VRPs:  437903 verified,  434586 final;
                router certs:       3 verified;
                 router keys:       3 verified,       3 final.
                       ASPAs:      66 verified,      66 final.

          .. versionchanged:: 0.11.0
             Reformat, sort alphabetically and add 
             :ref:`advanced-features:bgpsec` information
          .. versionadded:: 0.13.0
             Include :ref:`advanced-features:aspa`
