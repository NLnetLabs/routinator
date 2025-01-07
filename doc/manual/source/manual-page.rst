Manual Page
===========

Synopsis
--------

:program:`routinator` [``options``] :subcmd:`vrps` [``vrps-options``] [:samp:`-o {output-file}`] [:samp:`-f {format}`]

:program:`routinator` [``options``] :subcmd:`validate` [``validate-options``] [:samp:`-a {asn}`] [:samp:`-p {prefix}`]

:program:`routinator` [``options``] :subcmd:`server` [``server-options``]

:program:`routinator` [``options``] :subcmd:`update` [``update-options``]

:program:`routinator` :subcmd:`man` [:samp:`-o {file}`]

:program:`routinator` ``-h``

:program:`routinator` ``-V``

Description
-----------

Routinator collects and processes Resource Public Key Infrastructure (RPKI)
data. It validates the Route Origin Attestations contained in the data and
makes them available to your BGP routing workflow.

It can run in one-shot mode outputting a list of validated ROA payloads in
various formats, as a server for the RPKI-to-Router (RTR) protocol that many
routers implement to access the data, or via HTTP.

These modes and additional operations can be chosen via commands. For the
available commands, see `COMMANDS`_ below.

Options
-------

The available options are:

.. option:: -c path, --config=path

      Provides the path to a file containing basic configuration. If this
      option is not given, Routinator will try to use
      :file:`$HOME/.routinator.conf` if that exists. If that doesn't exist,
      either, default values for the options as described here are used.

      See `CONFIGURATION FILE`_ below for more information on the format and
      contents of the configuration file.

.. option:: -r dir, --repository-dir=dir

      Specifies the directory to keep the local repository in. This is
      the place where Routinator stores the RPKI data it has collected
      and thus is a copy of all the data referenced via the trust
      anchors.

      If omitted, defaults to :file:`$HOME/.rpki-cache/repository`.

.. option:: --no-rir-tals

      If present, Routinator will not use the bundled trust anchor locators
      (TALs) of the five Regional Internet Registries (RIRs).

      Trust anchor locators are the starting points for collecting and
      validating RPKI data. Each of the five RIRs provides a TAL that adds
      resources from their area. For normal production installations, these
      are the only TALs that should be used.

      Using this option as well as the :option:`--tal` and
      :option:`--extra-tals-dir` options you can change which TALs
      Routinator should use.

.. option:: --tal=name

      Use the bundled TAL with the given name in addition to any other TAL.

      Each RIR TAL is available through this option as well as TALs for a
      few select test environments. If you use this option with the name
      *list*, Routinator will print a list of all available bundled TALS and
      exit.

      The option can be given more than once.

.. option:: --extra-tals-dir=dir

      Specifies a directory containing additional trust anchor locators
      (TALs) to use. Routinator will use all files in this directory with
      an extension of *.tal* as TALs. These files need to be in the format
      described by :rfc:`8630`.

      Note that Routinator will use all TALs provided. That means that if a
      TAL in this directory is one of the bundled TALs, then these resources
      will be validated twice.

.. option:: -x file, --exceptions=file

      Provides the path to a local exceptions file. The option can be used
      multiple times to specify more than one file to use. Each file is a
      JSON file as described in :rfc:`8416`. It lists both route origins that
      should be filtered out of the output as well as origins that should be
      added.

.. option:: --strict

      If this option is present, the repository will be validated in strict
      mode following the requirements laid out by the standard documents very
      closely. With the current RPKI repository, using this option will lead
      to a rather large amount of invalid route origins and should therefore
      not be used in practice.

      See `RELAXED DECODING`_ below for more information.

.. option:: --stale=policy

      This option defines how deal with stale objects. In RPKI, manifests and
      CRLs can be stale if the time given in their *next-update* field is in
      the past, indicating that an update to the object was scheduled but
      didn't happen. This can be because of an operational issue at the
      issuer or an attacker trying to replay old objects.

      There are three possible policies that define how Routinator should
      treat stale objects.

      A policy of *reject* instructs Routinator to consider all stale objects
      invalid. This will result in all material published by the CA issuing
      this manifest and CRL to be invalid including all material of any child
      CA. 

      The *warn* policy will allow Routinator to consider any stale object to
      be valid. It will, however, print a warning in the log allowing an
      operator to follow up on the issue. 

      Finally, the *accept* policy will cause Routinator to quietly accept
      any stale object as valid.
      
      In Routinator 0.8.0 and newer, *reject* is the default policy if the 
      option is not provided. In version 0.7.0 the default for this option 
      was *warn*. In all previous versions *warn* was hard-wired.

.. option:: --unsafe-vrps=policy

      This option defines how to deal with "unsafe VRPs." If the address
      prefix of a VRP overlaps with any resources assigned to a CA that has
      been rejected because if failed to validate completely, the VRP is said
      to be unsafe since using it may lead to legitimate routes being flagged
      as RPKI invalid.

      There are three options how to deal with unsafe VRPs:

      A policy of *reject* will filter out these VRPs. Warnings will be
      logged to indicate which VRPs have been filtered

      The *warn* policy will log warnings for unsafe VRPs but will add them
      to the valid VRPs.

      Finally, the *accept* policy will quietly add unsafe VRPs to the valid
      VRPs. This is the default policy.

      For more information on the process of validation implemented in
      Routinator, see the section `VALIDATION`_ below.

.. option:: --unknown-objects=policy

      Defines how to deal with unknown types  of  RPKI  objects.  Currently,
      only certificates (.cer), CRLs (.crl), manifests (.mft), ROAs (.roa),
      and Ghostbuster Records (.gbr) are allowed to appear in the RPKI
      repository.

      There are, once more, three policies for dealing with an object of any
      other type:

      The *reject* policy will reject the object as well as the entire CA.
      Consequently, an unknown object appearing in a CA will mark all other
      objects issued by the CA as invalid as well.

      The policy of *warn* will log a warning, ignore the object, and accept
      all known objects issued by the CA.

      The similar policy of *accept* will quietly ignore the object and
      accept all known objects issued by the CA.

      The default policy if the option is missing is *warn*.

      Note that even if unknown objects are accepted, they must appear in
      the manifest and the hash over their content must match the one given
      in the manifest. If the hash does not match, the CA and all its objects
      are still rejected.

.. option:: --limit-v4-len=length, --limit-v6-len=length

      If present, defines the maximum length of IPv4 prefixes or IPv6
      prefixes, respectively, that will be included in the VRP data set. All
      VRPs for prefixes with a longer prefix length will be ignored. Note that
      only the prefix length itself, not the max length is considered.

      If either option is missing, VRPs for all prefixes of that particular
      address family are included.

.. option:: --allow-dubious-hosts

      As a precaution, Routinator will reject rsync and HTTPS URIs from RPKI
      data with dubious host names. In particular, it will reject the name
      *localhost*, host names that consist of IP addresses, and a host name
      that contains an explicit port.

      This option allows to disable this filtering.

.. option:: --fresh

      Delete and re-initialize the local data storage before starting. This
      option should be used when Routinator fails after reporting corrupt
      data storage.

.. option:: --disable-rsync

      If this option is present, rsync is disabled and only RRDP will be
      used.

.. option:: --rsync-command=command

      Provides the command to run for rsync. This is only the command itself.
      If you need to provide options to rsync, use the ``rsync-args``
      configuration file setting instead.

      If this option is not given, Routinator will simply run rsync and hope
      that it is in the path.

.. option:: --rsync-timeout=seconds

      Sets the number of seconds an rsync command is allowed to run before it
      is terminated early. This protects against hanging rsync commands that
      prevent Routinator from continuing. The default is 300 seconds which
      should be long enough except for very slow networks. Set the option to
      0 to disable the timeout.

.. option:: --disable-rrdp

      If this option is present, RRDP is disabled and only rsync will be
      used.

.. option:: --rrdp-fallback=policy

      Defines the circumstance when access via rsync should be tried for a
      CA that announces it can be updated via RRDP. In general, access via
      RRDP is less resource intensive and more secure than rsync and will
      therefore be preferred. This option specifies what to do when access
      to an RRDP repository fails.

      The policy ``never`` means that rsync is never tried for a CA that
      announces RRDP.

      The policy ``stale`` means that rsync is tried if an update via RRDP
      fails and there is no current local copy of the RRDP repository. A
      local copy is considered current if it was last updated within a
      time span chosen on a per-repository basis between the
      :option:`--refresh` time and :option:`--rrdp-fallback-time`.

      The policy ``new`` means that rsync is tried if an update via RRDP
      fails and there is no local copy of the RRDP repository at all. In
      other words, an update via RRDP has never succeeded for the repository.
      Choosing this policy allows a repository operator some leeway when
      first enabling RRDP support.

      The default policy if this option is not given is ``stale``.

.. option:: --rrdp-fallback-time=seconds

      Sets the maximum time in seconds since a last successful update of an
      RRDP repository before Routinator falls back to using rsync. The
      default is 3600 seconds. If the given value is smaller than twice the
      refresh time, it is silently increased to that value.
      
      The actual time is chosen at random between the refresh time and this
      value in order to spread out load on the rsync server.

.. option:: --rrdp-max-delta-count=count

      If the number of deltas necessary to update an RRDP repository is
      larger than the value provided by this option, the snapshot is used
      instead. If the option is missing, the default of 100 is used.

.. option:: --rrdp-max-delta-list-len=len
 
      If the number of deltas included in the notification file of an RRDP
      repository is larger than the value provided, the delta list is
      considered empty and the snapshot is used instead. If the option is
      missing, the default of 500 is used.

.. option:: --rrdp-timeout=seconds

      Sets the timeout in seconds for any RRDP-related network operation,
      i.e., connects, reads, and writes. If this option is omitted, the
      default timeout of 300 seconds is used. Set the option to 0 to disable
      the timeout.

.. option:: --rrdp-connect-timeout=seconds

      Sets the timeout in seconds for RRDP connect requests. If omitted, the
      general timeout will be used.

.. option:: --rrdp-tcp-keepalive=seconds

      Sets the value of the TCP keepalive duration in seconds for RRDP
      connections. The default if this option is omitted is 60 seconds. Set
      the option to 0 to disable the use of TCP keepalives.

.. option:: --rrdp-local-addr=addr

      If present, sets the local address that the RRDP client should bind to
      when doing outgoing requests.

.. option:: --rrdp-root-cert=path

      This option provides a path to a file that contains a certificate in
      PEM encoding that should be used as a trusted certificate for HTTPS
      server authentication. The option can be given more than once.

      Providing this option does *not* disable the set of regular HTTPS
      authentication trust certificates.

.. option:: --rrdp-proxy=uri

      This option provides the URI of a proxy to use for all HTTP connections
      made by the RRDP client. It can be either an HTTP or a SOCKS URI. The
      option can be given multiple times in which case proxies are tried in
      the given order.

.. option:: --rrdp-keep-responses=path

      If this option is enabled, the bodies of all HTTPS responses received
      from RRDP servers will be stored under *path*. The sub-path will be
      constructed using the components of the requested URI. For the
      responses to the notification files, the timestamp is appended to the
      path to make it possible to distinguish the series of requests made
      over time.

.. option:: --max-object-size=BYTES

      Limits the size of individual objects received via either rsync or RRDP
      to the given number of bytes. The default value if this option is not
      present is 20,000,000 (i.e., 20 MBytes). Use a value of 0 to disable
      the limit.

.. option:: --max-ca-depth=count

      The maximum number of CAs a given CA may be away from a trust anchor
      certificate before it is rejected. The default value is 32.

.. option:: --enable-bgpsec

      If this option is present, BGPsec router keys will be processed
      during validation and included in the produced data set.

.. option:: --enable-aspa

      If this option is present, ASPA assertions will be processed
      during validation and included in the produced data set.

.. option:: --aspa-provider-limit

      Limits the number of provider ASNs allowed in an ASPA object. If more
      providers are given, all ASPA assertions for the customer ASN are
      dropped to avoid false rejections. The default value if not changed
      via configuration or this option is 10,000 provider ASNs.

.. option:: --dirty

      If this option is present, unused files and directories will not be
      deleted from the repository directory after each validation run.

.. option:: --validation-threads=count

      Sets the number of threads to distribute work to for validation. Note
      that the current processing model validates trust anchors all in one
      go, so you are likely to see less than that number of threads used
      throughout the validation run.

.. option:: -v, --verbose

      Print more information. If given twice, even more information is
      printed.

      More specifically, a single :option:`-v` increases the log level from
      the default of *warn* to *info*, specifying it more than once increases
      it to *debug*.
      
      See `LOGGING`_ below for more information on what information is logged
      at the different levels.

.. option:: -q, --quiet

      Print less information. Given twice, print nothing at all.

      A single :option:`-q` will drop the log level to *error*. Repeating
      :option:`-q` more than once turns logging off completely.

.. option:: --syslog

      Redirect logging output to syslog.

      This option is implied if a command is used that causes Routinator to
      run in daemon mode.

.. option:: --syslog-facility=facility

      If logging to syslog is used, this option can be used to specify the
      syslog facility to use. The default is *daemon*.

.. option:: --logfile=path

      Redirect logging output to the given file.

.. option:: -h, --help

      Print some help information.

.. option:: -V, --version

      Print version information.

Commands
--------

Routinator provides a number of operations around the local RPKI repository.
These can be requested by providing different commands on the command line.

.. subcmd:: vrps

    This command requests that Routinator update the local repository and
    then validate the Route Origin Attestations in the repository and output
    the valid route origins, which are also known as Validated ROA Payloads
    or VRPs, as a list.

    .. option:: -o file, --output=file

           Specifies the output file to write the list to. If this option is
           missing or file is ``-`` the list is printed to standard output.

    .. option:: -f format, --format=format

           The output format to use. Routinator currently supports the
           following formats:

           csv
                  The list is formatted as lines of comma-separated values of
                  the autonomous system number, the prefix in slash notation,
                  the maximum prefix length, and an abbreviation for the
                  trust anchor the entry is derived from. The latter is the
                  name of the TAL file without the extension *.tal*. This can
                  be overwritten with the *tal-labels* config file option.

                  This is the default format used if the :option:`-f` option
                  is missing.

           csvcompat
                  The same as *csv* except that all fields are embedded in
                  double quotes and the autonomous system number is given
                  without the prefix ``AS``. This format is pretty much
                  identical to the CSV produced by the RIPE NCC Validator.

           csvext
                  An extended version of csv each line contains these
                  comma-separated values: the rsync URI of the ROA the line
                  is taken from (or "N/A" if it isn't from a ROA), the
                  autonomous system number, the prefix in slash notation, the
                  maximum prefix length, the not-before date and not-after
                  date of the validity of the ROA.

                  This format was used in the RIPE NCC RPKI Validator version
                  1. That version produces one file per trust anchor. This is
                  not currently supported by Routinator -- all entries will
                  be in one single output file.

           json
                  The list is placed into a JSON object with up to four
                  members: *roas* contains the validated route origin
                  authorizations, *routerKeys* contains the validated 
                  BGPsec router keys, *aspas* contains the validated
                  ASPA payload, and *metadata* contains some information
                  about the validation run itself. Of the first three, only
                  those members are present that have not been disabled or
                  excluded.

                  The *roas* member contains an array of objects with four
                  elements each: The autonomous system number of the network
                  authorized to originate a prefix in *asn*, the prefix in
                  slash notation in *prefix*, the maximum prefix length of
                  the announced route in *maxLength*, and the trust anchor
                  from which the authorization was derived in *ta*.

                  The *routerKeys* member contains an array of objects with
                  four elements each: The autonomous system using the router
                  key is given in *asn*, the key identifier as a string of
                  hexadecimal digits in *SKI*, the actual public key as a
                  Base 64 encoded string in *routerPublicKey*, and the trust
                  anchor from which the authorization was derived in *ta*.

                  The *aspa* member contains an array of objects with four
                  members each: The *customer* member contains the customer
                  ASN, *afi* the address family as either "ipv4" or "ipv6",
                  *providers* contains the provider ASN set as an array, and
                  the trust anchor from which the authorization was derived
                  in *ta*.

                  The output object also includes a member named *metadata*
                  which provides additional information. Currently, this is a
                  member *generated* which provides the time the list was
                  generated as a Unix timestamp, and a member *generatedTime*
                  which provides the same time but in the standard ISO date
                  format.

                  If only route origins are included, this format is identical
                  to that produced by the RIPE NCC
                  RPKI Validator except for different naming of the trust
                  anchor.
                  Routinator uses the name of the TAL file without the
                  extension *.tal* whereas the RIPE NCC Validator has a
                  dedicated name for each.

           jsonext
                  The list is placed into a JSON object with up to four
                  members: *roas* contains the validated route origin
                  authorizations, *routerKeys* contains the validated 
                  BGPsec router keys, *aspas* contains the validated
                  ASPA payload, and *metadata* contains some information
                  about the validation run itself. Of the first three, only
                  those members are present that have not been disabled or
                  excluded.

                  The *roas* member contains an array of objects with four
                  elements each: The autonomous system number of the network
                  authorized to originate a prefix in *asn*, the prefix in
                  slash notation in *prefix*, the maximum prefix length of
                  the announced route in *maxLength*, and extended
                  information about the source of the authorization in
                  *source*. 

                  The *routerKeys* member contains an array of objects with
                  four elements each: The autonomous system using the router
                  key is given in *asn*, the key identifier as a string of
                  hexadecimal digits in *SKI*, the actual public key as a
                  Base 64 encoded string in *routerPublicKey*, and extended
                  information about the source of the key is contained in
                  *source*.

                  The *aspa* member contains an array of objects with four
                  members each: The *customer* member contains the customer
                  ASN, *afi* the address family as either "ipv4" or "ipv6",
                  *providers* contains the provider ASN set as an array, and
                  information about the source of the data can be found in
                  *source*.

                  This source information the same for route origins and
                  router keys. It consists of an array. Each item in that
                  array is an object providing details of a source.
                  The object will have a *type* of *roa* if it was derived
                  from a valid ROA object, *cer* if it was derived from
                  a published router certificate, or *exception* if it was an
                  assertion in a local exception file.

                  For RPKI objects, *tal* provides the name of the trust
                  anchor locator the object was published under, *uri*
                  provides the rsync URI of the ROA or router certificate,
                  *validity* provides the validity of the ROA itself,
                  *chainValidity* the validity considering the validity of
                  the certificates along the validation chain, and
                  *stale* the time when any of the publication points along
                  the validation chain becomes stale.

                  For  assertions from local exceptions, *path* will provide
                  the path of the local exceptions file and, optionally,
                  *comment* will provide the comment if given for the
                  assertion.

                  The output object also includes a member named *metadata*
                  which provides additional information. Currently, this is a
                  member *generated* which provides the time the list was
                  generated as a Unix timestamp, and a member *generatedTime*
                  which provides the same time but in the standard ISO date
                  format.
                  
                  Please note that because of this additional information,
                  output in ``jsonext`` format will be quite large.

           slurm
                  The list is formatted as locally added assertions of a
                  local exceptions file defined by RFC 8416 (also known as
                  SLURM). The produced file will have empty validation
                  output filters.

           openbgpd
                  Choosing this format causes Routinator to produce a
                  *roa-set* configuration item for the OpenBGPD
                  configuration.

           bird1
                  Choosing this format causes Routinator to produce a *roa
                  table* configuration item for the BIRD1 configuration.

           bird2
                  Choosing this format causes Routinator to produce a *roa
                  table* configuration item for the BIRD2 configuration.

           rpsl
                  This format produces a list of RPSL objects with the
                  authorization in the fields *route*, *origin*, and
                  *source*. In addition, the fields *descr*, *mnt-by*,
                  *created*, and *last-modified*, are present with more or
                  less meaningful values.

           summary
                  This format produces a summary of the content of the RPKI
                  repository. For each trust anchor, it will print the number
                  of verified ROAs and VRPs. Note that this format does not
                  take filters into account. It will always provide numbers
                  for the complete repository.

           none
                  This format produces no output whatsoever.

    .. option:: -n, --noupdate

           The repository will not be updated before producing the list.

    .. option:: --complete

           If any of the rsync commands needed to update the repository
           failed, complete the operation but provide exit status 2. If this
           option is not given, the operation will complete with exit status
           0 in this case.

    .. option:: -a asn, --select-asn=asn

           Only output VRPs for the given ASN. The option can be given
           multiple times, in which case VRPs for all provided ASNs are
           provided. ASNs can be given with or without the prefix *AS*.

    .. option:: -p prefix, --select-prefix=prefix

           Only output VRPs with an address prefix that covers the given
           prefix, i.e., whose prefix is equal to or less specific than the
           given prefix. This will include VRPs regardless of their ASN and
           max length. In other words, the output will include all VRPs that
           need to be considered when deciding whether an announcement for
           the prefix is RPKI valid or invalid.

           The option can be given multiple times, in which case VRPs for all
           prefixes are provided. It can also be combined with one or more
           ASN selections. Then all matching VRPs are included. That is,
           selectors combine as "or" not "and".

    .. option:: -m, --more-specifics

           Include VRPs with prefixes that are more specifics of those given
           by the :option:`-p` option. Without this option, only VRPs with
           prefixes equal or less specific are included.

           Note that VRPs with more specific prefixes have no influence on
           whether a route is RPKI valid or invalid and therefore these VRPs
           are of an informational nature only.
    
    .. option:: --no-route-origins, --no-router-keys, --no-aspas

           These three options can be used to exclude the various payload
           types from being included in the output.


.. subcmd:: validate

       This command can be used to perform RPKI route origin validation for
       one or more route announcements. Routinator will determine whether the
       provided announcements are RPKI valid, invalid, or not found.
       
       A single route announcement can be given directly on the command line:

       .. option:: -a asn, --asn=asn

              The AS Number of the autonomous system that originated the
              route announcement. ASNs can be given with or without the
              prefix *AS*.

       .. option:: -p prefix, --prefix=prefix

              The address prefix the route announcement is for.

       .. option:: -j, --json

              A detailed analysis on the reasoning behind the validation is
              printed in JSON format including lists of the VRPs that caused
              the particular result. If this option is omitted, Routinator
              will only print the determined state.

       Alternatively, a list of route announcements can be read from a file
       or standard input.

       .. option:: -i file, --input=file
       
              If present, input is read from the given file. If the file is
              given is a single dash, input is read from standard output.
              
       .. option:: -j, --json

              If this option is provided, the input is assumed to be JSON
              format. It should consist of a single object with one  member
              *routes*  which contains an array of objects. Each object
              describes one route announcement through its *prefix* and *asn*
              members which contain a prefix and originating AS Number as
              strings, respectively.

              If the option is not provided, the input is assumed to consist
              of simple plain text with one route announcement per line,
              provided as a prefix followed by an ASCII-art arrow =>
              surrounded by white space and followed by the AS Number of
              originating autonomous system.

       The following additional options are available independently of the
       input method.

       .. option:: -o file, --output=file
       
              Output is written to the provided file. If the option is
              omitted or *file* is given as a single dash, output is written
              to standard output.

       .. option:: -n, --noupdate

              The repository will not be updated before performing
              validation.

       .. option:: --complete

              If any of the rsync commands needed to update the repository
              failed, complete the operation but provide exit status 2. If
              this option is not given, the operation will complete with exit
              status 0 in this case.

.. subcmd:: server

       This command causes Routinator to act as a server for the
       RPKI-to-Router (RTR) and HTTP protocols. In this mode, Routinator will
       read all the Trust Anchor Locators and will stay attached to the
       terminal unless the :option:`-d` option is given.

       The server will periodically update the local repository, every ten
       minutes by default, notify any clients of changes, and let them fetch
       validated data. It will not, however, reread the trust anchor
       locators. Thus, if you update them, you will have to restart
       Routinator.

       You can provide a number of addresses and ports to listen on for RTR
       and HTTP through command line options or their configuration file
       equivalent. Currently, Routinator will only start listening on these
       ports after an initial validation run has finished.

       It will not listen on any sockets unless explicitly specified. It will
       still run and periodically update the repository. This might be useful
       for use with :subcmd:`vrps` mode with the :option:`-n` option.

       .. option:: -d, --detach

              If present, Routinator will detach from the terminal after a
              successful start.

       .. option:: --rtr=addr:port

              Specifies a local address and port to listen on for incoming
              RTR connections.

              Routinator supports both protocol version 0 defined in
              :rfc:`6810` and version 1 defined in :rfc:`8210`. However, it
              does not support router keys introduced in version 1.  IPv6
              addresses must be enclosed in square brackets. You can provide
              the option multiple times to let Routinator listen on multiple
              address-port pairs.

       .. option:: --rtr-tls=addr:port

              Specifies a local address and port to listen for incoming
              TLS-encrypted RTR connections.

              The private key and server certificate given via the
              :option:`--rtr-tls-key` and :option:`--rtr-tls-cert` or their
              equivalent config file options will be used for connections.

              The option can be given multiple times, but the same key and
              certificate will be used for all connections.

       .. option:: --http=addr:port

              Specifies the address and port to listen on for incoming HTTP
              connections.  See `HTTP SERVICE`_ below for more information on
              the HTTP service provided by Routinator.

       .. option:: --http-tls=addr:port

              Specifies a local address and port to listen of for incoming
              TLS-encrypted HTTP connections.

              The private key and server certificate given via the
              :option:`--http-tls-key` and :option:`--http-tls-cert` or their
              equivalent config file options will be used for connections.

              The option can be given multiple times, but the same key and
              certificate will be used for all connections.

       .. option:: --listen-systemd

              The RTR listening socket will be acquired from systemd via
              socket activation. Use this option together with systemd's
              socket units to allow a Routinator running as a regular user to
              bind to the default RTR port 323.

              Currently, all TCP listener sockets handed over by systemd will
              be used for the RTR protocol.

       .. option:: --rtr-tcp-keepalive=seconds
        
              The number of seconds to wait before sending a TCP keepalive on
              an established RTR  connection. By  default, TCP keepalive is
              enabled on all RTR connections with an idle time of 60 seconds. 
              Set this option to 0 to disable keepalives.

              On some systems, notably OpenBSD, this option only enables TCP
              keepalives if set to any value other than 0. You will have to
              use the system's own mechanisms to change the idle times.

       .. option:: --rtr-client-metrics
       
              If provided, the server metrics will include separate metrics
              for every RTR client. Clients are identified by their RTR
              source IP address. This is disabled by default to avoid
              accidentally leaking information about the local network
              topology.

       .. option:: --rtr-tls-key

              Specifies the path to a file containing the private key to be
              used for RTR-over-TLS connections. The file has to contain
              exactly one private key encoded in PEM format.

       .. option:: --rtr-tls-cert

              Specifies the path to a file containing the server certificates
              to be used for RTR-over-TLS connections. The file has to
              contain one or more certificates encoded in PEM format.

       .. option:: --http-tls-key

              Specifies the path to a file containing the private key to be
              used for HTTP-over-TLS connections. The file has to contain
              exactly one private key encoded in PEM format.

       .. option:: --http-tls-cert

              Specifies the path to a file containing the server certificates
              to be used for HTTP-over-TLS connections. The file has to
              contain one or more certificates encoded in PEM format.

       .. option:: --refresh=seconds

              The amount of seconds the server should wait after having
              finished updating and validating the local repository before
              starting to update again. The next update will be earlier if
              objects in the repository expire earlier. The default value is
              600 seconds.

       .. option:: --retry=seconds

              The amount of seconds to suggest to an RTR client to wait
              before trying to request data again if that failed. The default
              value is 600 seconds, as recommended in :rfc:`8210`.

       .. option:: --expire=seconds

              The amount of seconds to an RTR client can keep using data if
              it cannot refresh it. After that time, the client should
              discard the data. Note that this value was introduced in
              version 1 of the RTR protocol and is thus not relevant for
              clients that only implement version 0. The default value, as
              recommended in :rfc:`8210`, is 7200 seconds.

       .. option:: --history=count

              In RTR, a client can request to only receive the changes that
              happened since the last version of the data it had seen. This
              option sets how many change sets the server will at most keep.
              If a client requests changes from an older version, it will get
              the current full set.

              Note that routers typically stay connected with their RTR
              server and therefore really only ever need one single change
              set. Additionally, if RTR server or router are restarted, they
              will have a new session with new change sets and need to
              exchange a full data set, too. Thus, increasing the value
              probably only ever increases memory consumption.

              The default value is 10.

       .. option:: --pid-file=path

              States a file which will be used in daemon mode to store the
              processes PID. While the process is running, it will keep the
              file locked.

       .. option:: --working-dir=path

              The working directory for the daemon process. In daemon mode,
              Routinator will change to this directory while detaching from
              the terminal.

       .. option:: --chroot=path

              The root directory for the daemon process. If this option is
              provided, the daemon process will change its root directory to
              the given directory. This will only work if all other paths
              provided via the configuration or command line options are
              under this directory.

       .. option:: --user=user-name

              The name of the user to change to for server mode. It this
              option is provided, Routinator will run as that user after the
              listening sockets for HTTP and RTR have been created. This may
              cause problems, if the user is not allowed to write to the
              directory given as repository directory or local exception
              files.

       .. option:: --group=group-name

              The name of the group to change to for server mode. It this
              option is provided, Routinator will run as that group after the
              listening sockets for HTTP and RTR have been created.


.. subcmd:: update

       Updates the local repository by resyncing all known publication
       points. The command will also validate the updated repository to
       discover any new publication points that appear in the repository and
       fetch their data.

       As such, the command really is a shortcut for running
       :program:`routinator` :subcmd:`vrps` :option:`-f` ``none``.

       .. option:: --complete

              If any of the rsync commands needed to update the repository
              failed, Routinator completes the operation and exits with
              status code 2. If this option is not given, the operation will
              complete with exit status 0 in this case.

.. subcmd:: dump

       Writes the content of all stored data to the file system. This is
       primarily intended for debugging but can be used to get access to the
       view of the RPKI data that Routinator currently sees.
       
       .. option:: -o dir, --output=dir
       
              Write the output to the given directory. If the option is omitted,
              the current directory is used.
              
       Three directories will be created in the output directory:
       
       The *rrdp* directory will contain all the files collected via RRDP
       from the various repositories. Each repository is stored in its own
       directory. The mapping between rpkiNotify URI and path is provided in
       the *repositories.json* file. For each repository, the files are
       stored in a directory structure based on the components of the file as
       rsync URI.
       
       The *rsync* directory contains all the files collected via rsync. The
       files are stored in a directory structure based on the components of
       the file's rsync URI.

       The *store* directory contains all the files used for validation.
       Files collected via RRDP  or rsync are copied to the store if they are
       correctly referenced by a valid manifest. This part contains one
       directory for each RRDP repository similarly structured to the *rrdp*
       directory and one additional directory *rsync* that contains files
       collected via rsync.

.. subcmd:: man

       Displays the manual page, i.e., this page.

       .. option:: -o file, --output=file

              If this option is provided, the manual page will be written to
              the given file instead of displaying it. Use - to output the
              manual page to standard output.

Configuration File
------------------

Instead of providing all options on the command line, they can also be
provided through a configuration file. Such a file can be selected through
the :option:`-c` option. If no configuration file is specified this way but a
file named :file:`$HOME/.routinator.conf` is present, this file is used.

The configuration file is a file in TOML format. In short, it consists of a
sequence of key-value pairs, each on its own line. Strings are to be enclosed
in double quotes. Lists can be given by enclosing a comma-separated list of
values in square brackets.

The configuration file can contain the following entries. All path values are
interpreted relative to the directory the configuration file is located in.
All values can be overridden via the command line options.

.. Glossary::

      repository-dir
            A string containing the path to the directory to store the local
            repository in. This entry is mandatory.

      no-rir-tals
            A boolean specifying whether the five RIR Trust Anchor Locators
            (TALs) should not be added to the set of evaluated TALs. If
            missing, the RIR TALs will be used.

      tals
            A list of strings, each containing the name of a bundled TAL to
            be added to the set of TALs to be evaluated.

      extra-tals-dir
            A string containing the path to a directory that contains
            additional TALs.

      exceptions
            A list of strings, each containing the path to a file with local
            exceptions. If missing, no local exception files are used.

      strict
            A boolean specifying whether strict validation should be
            employed. If missing, strict validation will not be used.

      stale
            A string specifying the policy for dealing with stale objects.

            reject
                  Consider all stale objects invalid rendering all material
                  published by the CA issuing the stale object to be invalid
                  including all material of any child CA. This is the default
                  policy if the value is missing.

            warn
                  Consider stale objects to be valid but print a warning to
                  the log.

            accept
                  Quietly consider stale objects valid.

      unsafe-vrps
            A string specifying the policy for dealing with unsafe VRPs.

            reject
                  Filter unsafe VRPs and add warning messages to the log.

            warn
                  Warn about unsafe VRPs in the log but add them to the final
                  set of VRPs.

            accept
                  Quietly add unsafe VRPs to the final set of VRPs.  This is
                  the default policy if the value is missing.

      unknown-objects
            A string specifying the policy for dealing with unknown RPKI
            object types.

            reject
                  Reject the object and its issuing CA.

            warn
                  Warn about the object but ignore it and accept the issuing
                  CA. This is the default policy if the value is missing.

            accept
                  Quietly ignore the object and accept the issuing CA.

      limit-v4-len
            An integer value which, if present, limits the length of IPv4
            prefixes for which VPRs are included in the data set to the given
            value.

      limit-v6-len
            An integer value which, if present, limits the length of IPv6
            prefixes for which VPRs are included in the data set to the given
            value.

      allow-dubious-hosts
            A boolean value that, if present and true, disables Routinator's
            filtering of dubious host names in rsync and HTTPS URIs from RPKI
            data.

      disable-rsync
            A boolean value that, if present and true, turns off the use of
            rsync.

      rsync-command
            A string specifying the command to use for running rsync. The
            default is simply *rsync*.

      rsync-args
            A list of strings containing additional arguments to be passed
            to the rsync command. Each string is an argument of its own.

            The options ``-rtO --delete`` are always passed to the command.
            The options listed in the option are added to it.

            If the option is not provided, Routinator will add ``-z`` and
            ``--no-motd``, as well as ``--contimeout=10`` if it is supported
            by the rsync command, and ``--max-size`` if the
            ``max-object-size`` option has not been set to 0.

      rsync-timeout
            An integer value specifying the number seconds an rsync command
            is allowed to run before it is being terminated. The default if
            the value is missing is 300 seconds. Set the value to 0 to turn
            the timeout off.

      disable-rrdp
            A boolean value that, if present and true, turns off the use of
            RRDP.

      rrdp-fallback
            A string value specifying the circumstances under which an update
            via rsync is tried if an update via RRDP fails. See
            :option:`--rrdp-fallback` for details on the available policies.

      rrdp-fallback-time
            An integer value specifying the maximum number of seconds since a
            last successful update of an RRDP repository before Routinator
            falls back to using rsync. The default in case the value is
            missing is 3600 seconds. If the value provided is smaller than
            twice the refresh time, it is silently increased to that value.

      rrdp-max-delta-count
            An integer value that specifies the maximum number of deltas
            necessary to update an RRDP repository before using the snapshot
            instead. If the value is missing, the default of 100 is used.

      rrdp-max-delta-list-len
            An integer value that specifies the maximum number of deltas
            listed the notification file of an RRDP repository before the
            list is considered empty and the snapshot is used instead.
            If the value is missing, the default of 500 is used.

      rrdp-timeout
            An integer value that provides a timeout in seconds for all
            individual RRDP-related network operations, i.e., connects,
            reads, and writes. If the value is missing, a default timeout of
            300 seconds will be used. Set the value to 0 to turn the timeout
            off.

      rrdp-connect-timeout
            An integer value that, if present, sets a separate timeout in
            seconds for RRDP connect requests only.

      rrdp-tcp-keepalive
            An integer value that provides the duration in seconds for the
            TCP keepalive option on RRDP connections. If the value is missing,
            a duration of 60 seconds is used. Set the value to 0 to disable
            the use of TCP keepalive for RRDP connections.

      rrdp-local-addr
            A string value that provides the local address to be used by RRDP
            connections.

      rrdp-root-certs
            A list of strings each providing a path to a file containing a
            trust anchor certificate for HTTPS authentication of RRDP
            connections. In addition to the certificates provided via this
            option, the system's own trust store is used.

      rrdp-proxies
            A list of string each providing the URI for a proxy for outgoing
            RRDP connections. The proxies are tried in order for each
            request. HTTP and SOCKS5 proxies are supported.

      rrdp-keep-responses
            A string containing a path to a directory into which the bodies
            of all HTTPS responses received from RRDP servers will be stored.
            The sub-path will be constructed using the components of the
            requested URI. For the responses to the notification files, the
            timestamp is appended to the path to make it possible to
            distinguish the series of requests made over time.

      max-object-size
            An integer value that provides a limit for the size of individual
            objects received via either rsync or RRDP to the given number of
            bytes. The default value if this option is not present is
            20,000,000 (i.e., 20 MBytes). A value of 0 disables the limit.

      max-ca-depth
            An integer value that specifies the maximum number of CAs a given
            CA may be away from a trust anchor certificate before it is
            rejected. If the option is missing, a default of 32 will be used.

      enable-bgpsec
            A boolean value specifying whether BGPsec router keys should be
            included in the published dataset. If false or missing, no router
            keys will be included.


      enable-aspa
            A boolean value specifying whether ASPA assertions should be
            included in the published dataset. If false or missing, no ASPA
            assertions will be included.

      aspa_provider_limit
            An integer value specifying the maximum number of provider ASNs
            allowed in an ASPA object. If more providers are given, all ASPA
            assertions for the customer ASN are dropped to avoid false
            rejections. If the option is missing, a default of 10,000
            provider ASNs is used.

      dirty
            A boolean value which, if true, specifies that unused files and
            directories should not be deleted from the repository directory
            after each validation run. If left out, its value will be false
            and unused files will be deleted.

      validation-threads
            An integer value specifying the number of threads to be used
            during validation of the repository. If this value is missing,
            the number of CPUs in the system is used.

      log-level
            A string value specifying the maximum log level for which log
            messages should be emitted. The default is *warn*.

            See `LOGGING`_ below for more information on what information is
            logged at the different levels.

      log
            A string specifying where to send log messages to. This can be
            one of the following values:

            default
                  Log messages will be sent to standard error if Routinator
                  stays attached to the terminal or to syslog if it runs in
                  daemon mode.

            stderr
                  Log messages will be sent to standard error.

            syslog
                  Log messages will be sent to syslog.

            file
                  Log messages will be sent to the file specified through
                  the log-file configuration file entry.

            The default if this value is missing is, unsurprisingly,
            *default*.

      log-file
            A string value containing the path to a file to which log
            messages will be appended if the log configuration value is set
            to file. In this case, the value is mandatory.

      syslog-facility
            A string value specifying the syslog facility to use for logging
            to syslog. The default value if this entry is missing is
            *daemon*.

      rtr-listen
            An array of string values each providing an address and port on
            which the RTR server should listen in TCP mode. Address and port
            should be separated by a colon. IPv6 address should be enclosed
            in square brackets.

      rtr-tls-listen
            An array of string values each providing an address and port
            on which the RTR server should listen in TLS mode. Address and
            port should be separated by a colon. IPv6 address should be
            enclosed in square brackets.

      http-listen
            An array of string values each providing an address and port
            on which the HTTP server should listene. Address and
            port should be separated by a colon. IPv6 address should be
            enclosed in square brackets.

      http-tls-listen
            An array of string values each providing an address and port
            on which the HTTP server should listen in TLS mode. Address and
            port should be separated by a colon. IPv6 address should be
            enclosed in square brackets.

      listen-systemd
            The RTR TCP listening socket will be acquired from systemd via
            socket activation. Use this option together with systemd's socket
            units to allow Routinator running as a regular user to bind to
            the default RTR port 323.

      rtr-tcp-keepalive
            An integer value specifying the number of seconds to wait before
            sending a TCP keepalive on an established RTR connection. If this
            option is missing, TCP keepalive will be enabled on all RTR
            connections with an idle time of 60 seconds. If this option is
            present and set to zero, TCP keepalives are disabled.

            On some systems, notably OpenBSD, this option only enables TCP
            keepalives if set to any value other than 0. You will have to
            use the system's own mechanisms to change the idle times.

      rtr-client-metrics
            A boolean value specifying whether server metrics should include
            separate metrics for every RTR client. If the value is missing,
            no RTR client metrics will be provided.

      rtr-tls-key
            A string value providing the path to a file containing the
            private key to be used by the RTR server in TLS mode. The file
            must contain one private key in PEM format.

      rtr-tls-cert
            A string value providing the path to a file containing the server
            certificates to be used by the RTR server in TLS mode. The file
            must contain one or more certificates in PEM format.

      http-tls-key
            A string value providing the path to a file containing the
            private key to be used by the HTTP server in TLS mode. The file
            must contain one private key in PEM format.

      http-tls-cert
            A string value providing the path to a file containing the server
            certificates to be used by the HTTP server in TLS mode. The file
            must contain one or more certificates in PEM format.

      refresh
            An integer value specifying the number of seconds Routinator
            should wait between consecutive validation runs in server mode.
            The next validation run will happen earlier, if objects expire
            earlier. The default is 600 seconds.

      retry
            An integer value specifying the number of seconds an RTR client
            is requested to wait after it failed to receive a data set. The
            default is 600 seconds.

      expire
            An integer value specifying the number of seconds an RTR client
            is requested to use a data set if it cannot get an update before
            throwing it away and continuing with no data at all. The default
            is 7200 seconds if it cannot get an update before throwing it
            away and continuing with no data at all. The default is 7200
            seconds.

      history-size
            An integer value specifying how many change sets Routinator
            should keep in RTR server mode. The default is 10.

      pid-file
            A string value containing a path pointing to the PID file to be
            used in daemon mode.

      working-dir
            A string value containing a path to the working directory for the
            daemon process.

      chroot
            A string value containing the path any daemon process should use
            as its root directory.

      user
            A string value containing the user name a daemon process should
            run as.

      group
            A string value containing the group name a daemon process should
            run as.

      tal-labels
            An array containing arrays of two string values mapping the name
            of a TAL file (without the path but including the extension) as
            given by the first string to the name of the TAL to be included
            where the TAL is referenced in output as given by the second
            string.

            If the options missing or if a TAL isn't mentioned in the option,
            Routinator will construct a name for the TAL by using its file
            name (without the path) and dropping the extension.

HTTP Service
------------

Routinator can provide an HTTP service allowing to fetch the Validated ROA
Payload in various formats. The service does not support HTTPS and should
only be used within the local network.

The service only supports GET requests with the following paths:

/metrics
      Returns a set of monitoring metrics in the format used by Prometheus.

/status
      Returns the current status of the Routinator instance. This is similar
      to the output of the **/metrics** endpoint but in a more human friendly
      format.

/api/v1/status
      Returns the current status in JSON format.

/log
      Returns the logging output of the last validation run. The log level
      matches that set upon start.
      
      Note that the output is collected after each validation run and is
      therefore only available after the initial run has concluded.

/version
      Returns the version of the Routinator instance.

/api/v1/validity/as-number/prefix
      Returns a JSON object describing whether the route announcement given
      by its origin AS Number and address prefix is RPKI valid, invalid, or
      not found.  The returned object is compatible with that provided by the
      RIPE NCC RPKI Validator. For more information, see
      https://ripe.net/support/documentation/developer-documentation/rpki-validator-api

/validity?asn=as-number&prefix=prefix
      Same as above but with a more form-friendly calling convention.

/json-delta, /json-delta?session=session&serial=serial
      Returns a JSON object with the changes since the dataset version
      identified by the *session* and *serial* query parameters. If a delta
      cannot be produced from that version, the full data set is returned and
      the member *reset* in the object will be set to *true*. In either case,
      the members *session* and *serial* identify the version of the data set
      returned and their values should be passed as the query parameters in a
      future request.

      The members *announced* and *withdrawn* contain arrays with route
      origins that have been announced and withdrawn, respectively, since the
      provided session and serial. If *reset* is *true*, the *withdrawn*
      member is not present.

/json-delta/notify, /json-delta/notify?session=session&serial=serial
      Returns a JSON object with two members *session* and *serial* which
      contain the session ID and serial number of the current data set.

      If the *session* and *serial* query parameters are provided, and the
      session ID and serial number of the current data set are identical
      to the provided values, the request will not return until a new data
      set is available. This can be used as a means to get notified when
      the data set has been updated.

In addition, the current set of VRPs is available for each output format at a
path with the same name as the output format. E.g., the CSV output is
available at ``/csv``.

These paths accept selector expressions to limit the VRPs returned in the
form of a query string. The field ``select-asn`` can be used to filter for
ASNs and the field ``select-prefix`` can be used to filter for prefixes. The
fields can be repeated multiple times.

In addition, the query parameter ``include=more-specifics`` will cause the
inclusion of VRPs for more specific prefixes of prefixes given via
``select-prefix``.

Finally, the query parameter ``exclude`` can be used to exclude certain
payload types from the response. The values ``routeOrigins``, ``routerKeys``,
and ``aspas`` disable inclusion of route origins, router keys, and ASPAs,
respectively. The values can either be given in separate ``exclude``
parameters or included in one separated by commas.

These parameters work in the same way as the options of the same name to the
:subcmd:`vrps` command.

Logging
-------

In order to allow diagnosis of the VRP data set as well as its overall
health, Routinator logs an extensive amount of information. The log levels
used by syslog are utilized to allow filtering this information for
particular use cases.

The log levels represent the following information:

error
      Information related to events that prevent Routinator from continuing
      to operate at all as well as all issues related to local configuration
      even if Routinator will continue to run.

warn
      Information about events and data that influences the set of VRPs
      produced by Routinator. This includes failures to communicate with
      repository servers, or encountering invalid objects.

info
      Information about events and data that could be considered abnormal but
      do not influence the set of VRPs produced. For example, when filtering
      of unsafe VRPs is disabled, the unsafe VRPs are logged with this level.

debug
      Information about the internal state of Routinator that may be useful
      for, well, debugging.

Validation
----------

In :subcmd:`vrps` and :subcmd:`server` mode, Routinator will produce a set of
VRPs from the data published in the RPKI repository. It will walk over all
certification authorities (CAs) starting with those referred to in the
configured TALs.

Each CA is checked whether all its published objects are present, correctly
encoded, and have been signed by the CA. If any of the objects fail this
check, the entire CA will be rejected. If an object of an unknown  type  is
encountered, the behaviour depends on the ``unknown-objects`` policy. If this
policy has a value of *reject* the entire CA will be rejected. In this case,
only certificates (.cer), CRLs (.crl), manifests (.mft), ROAs (.roa), and
Ghostbuster records (.gbr) will be accepted.

If a CA is rejected, none of its ROAs will be added to the VRP set but also
none of its child CAs will be considered at all; their published data will
not be fetched or validated.

If a prefix has its ROAs published by different CAs, this will lead to some
of its VRPs being dropped while others are still added. If the VRP for the
legitimately announced route is among those having been dropped, the route
becomes RPKI invalid. This can happen both by operator error or through an
active attack.

In addition, if a VRP for a less specific prefix exists that covers the
prefix of the dropped VRP, the route will be invalidated by the less specific
VRP.

Because of this risk of accidentally or maliciously invalidating routes, VRPs
that have address prefixes overlapping with resources of rejected CAs are
called *unsafe VRPs*.

In order to avoid these situations and instead fall back to an RPKI unknown
state for such routes, Routinator allows to filter out these unsafe VRPs.
This can be enabled via the ``--unsafe-vrps=reject`` command line option or
setting ``unsafe-vrps=reject`` in the config file.

By default, this filter is currently disabled but warnings are logged about
unsafe VRPs. This allows to assess the operation impact of such a filter.
Depending on this assessment, the default may change in future versions.

One exception from this rule are CAs that have the full address space
assigned, i.e., 0.0.0.0/0 and ::/0. Adding these to the filter would wipe out
all VRPs. These prefixes are used by the RIR trust anchors to avoid having to
update these often. However, each RIR has its own address space so losing all
VRPs should something happen to a trust anchor is unnecessary.

Relaxed Decoding
----------------

The documents defining RPKI include a number of very strict rules regarding
the formatting of the objects published in the RPKI repository. However,
because RPKI reuses existing technology, real-world applications produce
objects that do not follow these strict requirements.

As a consequence, a significant portion of the RPKI repository is actually
invalid if the rules are followed. We therefore introduce two decoding modes:
strict and relaxed. Strict mode rejects any object that does not pass all
checks laid out by the relevant RFCs. Relaxed mode ignores a number of these
checks.

This memo documents the violations we encountered and are dealing with in
relaxed decoding mode.


   Resource Certificates (:rfc:`6487`)
       Resource certificates are defined as a profile on the more general
       Internet PKI certificates defined in :rfc:`5280`.


       Subject and Issuer
              The RFC restricts the type used for CommonName attributes to
              PrintableString, allowing only a subset of ASCII characters,
              while :rfc:`5280` allows a number of additional string types.
              At least one CA produces resource certificates with
              Utf8Strings.

              In relaxed mode, we will only check that the general structure
              of the issuer and subject fields are correct and allow any
              number and types of attributes. This seems justified since RPKI
              explicitly does not use these fields.

   Signed Objects (:rfc:`6488`)
       Signed objects are defined as a profile on CMS messages defined in
       :rfc:`5652`.

       DER Encoding
              :rfc:`6488` demands all signed objects to be DER encoded while
              the more general CMS format allows any BER encoding -- DER is a
              stricter subset of the more general BER. At least one CA does
              indeed produce BER encoded signed objects.

              In relaxed mode, we will allow BER encoding.

              Note that this isn't just nit-picking. In BER encoding, octet
              strings can be broken up into a sequence of sub-strings. Since
              those strings are in some places used to carry encoded content
              themselves, such an encoding does make parsing significantly
              more difficult. At least one CA does produce such broken-up
              strings.

Signals
-------

SIGUSR1: Reload TALs and restart validation
   When receiving SIGUSR1, Routinator will attempt to reload the TALs and, if
   that succeeds, restart validation. If loading the TALs fails, Routinator
   will exit.

SIGUSR2: Re-open log file
   When receiving SIGUSR2 and logging to a file is enabled, Routinator will
   re-open the log file. If this fails, Routinator will exit.

Exit Status
-----------

Upon success, the exit status 0 is returned. If any fatal error happens, the
exit status will be 1. Some commands provide a :option:`--complete` option
which will cause the exit status to be 2 if any of the rsync commands to
update the repository fail.
