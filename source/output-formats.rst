.. _doc_routinator_output_formats:

VRP Output Formats
==================

.. versionadded:: 0.9
   The ``jsonext`` format

Routinator can perform RPKI validation as a one-time operation or run as a
daemon. In both operating modes validated ROA payloads (VRPs) can be generated
in a wide range of output formats for various use cases.

.. Tip:: In many of the output formats, the name of the trust anchor from where
         the VRP originated is provided. This name is derived from the file name
         of the TAL, without  the *.tal* extension. If you would like a
         different name, the *tal-label* option in  the :ref:`configuration file
         <doc_routinator_configuration>` lets you create a mapping between the
         file name and your desired label.

csv
      The list is formatted as lines of comma-separated values of the prefix in
      slash notation, the maximum prefix length, the autonomous system number,
      and the name of the trust anchor the entry is derived from. 
      
      .. code-block:: text
         
         ASN,IP Prefix,Max Length,Trust Anchor
         AS196615,2001:7fb:fd03::/48,48,ripe
         AS196615,2001:7fb:fd04::/48,48,ripe
         AS196615,93.175.147.0/24,24,ripe
      
csvcompat
       This is the same as the *csv* format except that all fields are embedded
       in double quotes and the autonomous system number is given without the
       prefix *AS*. This format is pretty much identical to the CSV format 
       produced by the RIPE NCC RPKI Validator.
       
       .. code-block:: text
          
          "ASN","IP Prefix","Max Length","Trust Anchor"
          "196615","2001:7fb:fd03::/48","48","ripe"
          "196615","2001:7fb:fd04::/48","48","ripe"
          "196615","93.175.147.0/24","24","ripe"
          
csvext
      This is an extended version of the *csv* format, which was used by the
      RIPE NCC RPKI Validator 1.x. Each line contains these comma-separated
      values: the rsync URI of the ROA the line is taken from (or "N/A" if it
      isn't from a ROA), the autonomous system number, the prefix in slash
      notation, the maximum prefix length, and lastly the not-before and
      not-after date of the validity of the ROA.
      
      .. code-block:: text
         
         URI,ASN,IP Prefix,Max Length,Not Before,Not After
         rsync://rpki.ripe.net/repository/DEFAULT/73/fe2d72-c2dd-46c1-9429-e66369649411/1/49sMtcwyAuAW2lVDSQBGhOHd9og.roa,AS196615,2001:7fb:fd03::/48,48,2021-05-03 14:51:30,2022-07-01 00:00:00
         rsync://rpki.ripe.net/repository/DEFAULT/73/fe2d72-c2dd-46c1-9429-e66369649411/1/49sMtcwyAuAW2lVDSQBGhOHd9og.roa,AS196615,2001:7fb:fd04::/48,48,2021-05-03 14:51:30,2022-07-01 00:00:00
         rsync://rpki.ripe.net/repository/DEFAULT/73/fe2d72-c2dd-46c1-9429-e66369649411/1/49sMtcwyAuAW2lVDSQBGhOHd9og.roa,AS196615,93.175.147.0/24,24,2021-05-03 14:51:30,2022-07-01 00:00:00
         
json
      The VRP list is placed into a JSON object with a single element *roas*
      which contains an array of objects with four elements each: The autonomous
      system number of the network authorised to originate a prefix in *asn*,
      the prefix in slash notation in *prefix*, the maximum prefix length of the
      announced route in *maxLength*, and the trust anchor from which the
      authorisation was derived in *ta*. This format is identical to that
      produced by the RIPE NCC RPKI Validator except for different naming of the
      trust anchor. 
      
      .. code-block:: text
         
         {
           "roas": [
            { "asn": "AS196615", "prefix": "2001:7fb:fd03::/48", "maxLength": 48, "ta": "ripe" },
            { "asn": "AS196615", "prefix": "2001:7fb:fd04::/48", "maxLength": 48, "ta": "ripe" },
            { "asn": "AS196615", "prefix": "93.175.147.0/24", "maxLength": 24, "ta": "ripe" }
           ]
         }

jsonext
      The list is placed into a JSON object with a single element *roas* which
      contains an array of objects with four elements each: The autonomous
      system number of the network authorized to originate a prefix in *asn*,
      the prefix in slash notation  in *prefix*, the maximum prefix length of
      the announced route  in *maxLength*.

      Extensive information about the source of the object is given in the
      array *source*. Each item in that array is an object providing details of
      a source of the VRP. The object will have a type of roa if it was derived
      from a valid ROA object or exception if it was an assertion in a local
      exception file.

      For ROAs, *uri* provides the rsync URI of the ROA, *validity* provides the
      validity of the ROA itself, and *chainValidity* the validity considering
      the validity of the certificates along the validation chain.

      For assertions from :ref:`local exceptions
      <doc_routinator_local_exceptions>`, *path* will provide the path of the
      local exceptions file and, optionally, *comment* will provide the comment
      if given for the assertion.

      Please note that the output in ``jsonext`` format will be quite large.
      
      .. code-block:: text
      
          {
            "roas": [{
              "asn": "AS196615",
              "prefix": "93.175.147.0/24",
              "maxLength": 24,
              "source": [{
                "type": "roa",
                "uri": "rsync://rpki.ripe.net/repository/DEFAULT/73/fe2d72-c2dd-46c1-9429-e66369649411/1/49sMtcwyAuAW2lVDSQBGhOHd9og.roa",
                "validity": {
                  "notBefore": "2021-01-01T04:39:56Z",
                  "notAfter": "2022-07-01T00:00:00Z"
                },
                "chainValidity": {
                  "notBefore": "2021-05-06T12:51:30Z",
                  "notAfter": "2022-07-01T00:00:00Z"
                }
              }]
            }]
          }

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
      This format produces a list of :abbr:`RPSL (Routing Policy Specification
      Language)` objects with the authorisation in the fields *route*, *origin*,
      and *source*. In addition, the fields *descr*, *mnt-by*, *created*, and
      *last-modified*, are present with more or less meaningful values.
      
      .. code-block:: text
         
         route: 93.175.147.0/24
         origin: AS196615
         descr: RPKI attestation 
         mnt-by: NA
         created: 2021-05-07T14:28:17Z
         last-modified: 2021-05-07T14:28:17Z
         source: ROA-RIPE-RPKI-ROOT
      
summary
      This format produces a summary of the content of the RPKI repository. For
      each trust anchor, it will print the number of verified ROAs and VRPs.
      Note that this format does not take filters into account. It will always
      provide numbers for the complete repository.
      
      .. code-block:: text
      
         Summary at 2021-05-04 08:16:17.979912 UTC
         afrinic: 1403 verified ROAs, 2072 verified VRPs, 0 unsafe VRPs, 2039 final VRPs.
         lacnic: 7250 verified ROAs, 14862 verified VRPs, 0 unsafe VRPs, 13554 final VRPs.
         apnic: 14567 verified ROAs, 70454 verified VRPs, 0 unsafe VRPs, 70369 final VRPs.
         ripe: 23495 verified ROAs, 125031 verified VRPs, 0 unsafe VRPs, 125029 final VRPs.
         arin: 30026 verified ROAs, 35806 verified VRPs, 0 unsafe VRPs, 30207 final VRPs.
         total: 76741 verified ROAs, 248225 verified VRPs, 0 unsafe VRPs, 241198 final VRPs.

