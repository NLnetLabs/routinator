.. _doc_routinator_manpage:

Manual Page
===========

:command:`routinator` - RPKI relying party software

:Date:       2021-02-02
:Author:     Martin Hoffmann
:Copyright:  2019-2020 - NLnet Labs
:Version:    0.8.3

Synopsis
--------

.. raw:: html

  <p><strong class="command">routinator</strong> <code class="xref std
  std-option docutils literal notranslate"><span
  class="pre">options</span></code> <a class="reference internal"
  href="#subcmd-init"><code class="xref std std-subcmd docutils literal
  notranslate"><span class="pre">init</span></code></a> <code class="xref std
  std-option docutils literal notranslate"><span
  class="pre">init-options</span></code></p>

  <p><strong class="command">routinator</strong> <code class="xref std
  std-option docutils literal notranslate"><span
  class="pre">options</span></code> <a class="reference internal"
  href="#subcmd-vrps"><code class="xref std std-subcmd docutils literal
  notranslate"><span class="pre">vrps</span></code></a> <code class="xref std
  std-option docutils literal notranslate"><span
  class="pre">vrps-options</span></code> <a class="reference
  internal" href="#cmdoption-o"><code class="xref std std-option docutils
  literal notranslate"><span class="pre">-o
  <var>output-file</var></span></code></a> <a class="reference internal"
  href="#cmdoption-format"><code class="xref std std-option docutils literal
  notranslate"><span class="pre">-f <var>format</var></span></code></a></p>

  <p><strong class="command">routinator</strong> <code class="xref std
  std-option docutils literal notranslate"><span
  class="pre">options</span></code> <a class="reference internal"
  href="#subcmd-validate"><code class="xref std std-subcmd docutils literal
  notranslate"><span class="pre">validate</span></code></a> <code class="xref std
  std-option docutils literal notranslate"><span
  class="pre">validate-options</span></code> <a class="reference internal"
  href="#cmdoption-asn"><code class="xref std std-option docutils literal
  notranslate"><span class="pre">-a <var>asn</var></span></code></a> <a
  class="reference internal" href="#cmdoption-prefix"><code class="xref std
  std-option docutils literal notranslate"><span class="pre">-p
  <var>prefix</var></span></code></a></p>

  <p><strong class="command">routinator</strong> <code class="xref std
  std-option docutils literal notranslate"><span
  class="pre">options</span></code> <a class="reference internal"
  href="#subcmd-server"><code class="xref std std-subcmd docutils literal
  notranslate"><span class="pre">server</span></code></a> <code class="xref std
  std-option docutils literal notranslate"><span
  class="pre">server-options</span></code></p>

  <p><strong class="command">routinator</strong> <code class="xref std
  std-option docutils literal notranslate"><span
  class="pre">options</span></code> <a class="reference internal"
  href="#subcmd-update"><code class="xref std std-subcmd docutils literal
  notranslate"><span class="pre">update</span></code></a> <code class="xref std
  std-option docutils literal notranslate"><span
  class="pre">update-options</span></code></p>

  <p><strong class="command">routinator</strong> <a class="reference internal"
  href="#subcmd-man"><code class="xref std std-subcmd docutils literal
  notranslate"><span class="pre">man</span></code></a> <a class="reference
  internal" href="#cmdoption-output"><code class="xref std std-option docutils
  literal notranslate"><span class="pre">-o
  <var>file</var></span></code></a></p>

  <p><strong class="command">routinator</strong> <a
  class="reference internal" href="#cmdoption-h"><code class="xref std
  std-option docutils literal notranslate"><span
  class="pre">-h</span></code></a></p>

  <p><strong class="command">routinator</strong> <a class="reference internal"
  href="#cmdoption-version"><code class="xref std std-option docutils literal
  notranslate"><span class="pre">-V</span></code></a></p>

Description
-----------

Routinator collects and processes Resource Public Key Infrastructure
(RPKI) data. It validates the Route Origin Attestations contained in
the data and makes them available to your BGP routing workflow.

It can either run in one-shot mode outputting a list of validated route
origins in various formats or as a server for the RPKI-to-Router (RTR)
protocol that routers often implement to access the data, or via HTTP.

These modes and additional operations can be chosen via commands. For
the available commands, see `Commands`_ below.

Options
-------

The available options are:

.. option:: -c path, --config=path

    Provides the path to a file containing basic configuration. If this option
    is not given, Routinator will try to use :file:`$HOME/.routinator.conf` if
    that exists. If that doesn't exist, either, default values for the options
    as described here are used.

    See `Configuration File`_ below for more information on the format and
    contents of the configuration file.

.. option:: -b dir, --base-dir=dir

    Specifies the base directory to keep status information in. Unless
    overwritten by the :option:`-r` or :option:`-t` options, the local
    repository will be kept in the sub-directory repository and the TALs will
    be kept in the sub-directory :file:`tals`.

    If omitted, the base directory defaults to :file:`$HOME/.rpki-cache`.

.. option:: -r dir, --repository-dir=dir

      Specifies the directory to keep the local repository in. This is
      the place where Routinator stores the RPKI data it has collected
      and thus is a copy of all the data referenced via the trust anchors.

.. option:: -t dir, --tal-dir=dir

      Specifies the directory containing the trust anchor locators (TALs) to
      use. Trust anchor locators are the starting points for collecting and
      validating RPKI data. See `Trust Anchor Locators`_ for more information
      on what should be present in this directory.

.. option:: -x file, --exceptions=file

      Provides the path to a local exceptions file. The option can be used
      multiple times to specify more than one file to use. Each file is a JSON
      file as described in :rfc:`8416`. It lists both route origins that should
      be filtered out of the output as well as origins that should be added.

.. option:: --strict

      If this option is present, the repository will be validated in strict
      mode following the requirements laid out by the standard documents very
      closely. With the current RPKI repository, using this option will lead to
      a rather large amount of invalid route origins and should therefore not be
      used in practice.

      See `Relaxed Decoding`_ below for more information.

.. option:: --stale=policy

      This option defines how deal with stale objects. In RPKI, manifests and
      CRLs can be stale if the time given in their *next-update* field is in the
      past, indicating that an update to the object was scheduled but didn't
      happen. This can be because of an operational issue at the issuer or an
      attacker trying to replay old objects.

      There are three possible policies that define how Routinator should treat
      stale objects.

      A policy of *reject* instructs Routinator to consider all stale objects
      invalid. This will result in all material published by the CA issuing this
      manifest and CRL to be invalid including all material of any child CA.

      The *warn* policy will allow Routinator to consider any stale object to be
      valid. It will, however, print a warning in the log allowing an operator
      to follow up on the issue. This is the default policy if the option is not
      provided.

      Finally, the *accept* policy will cause Routinator to quietly accept any
      stale object as valid.

.. option:: --unsafe-vrps=policy

      This option defines how to deal with "unsafe VRPs." If the address  prefix
      of a VRP overlaps with any resources assigned to a CA that has been
      rejected because if failed to  validate  completely, the VRP is said to be
      unsafe since using it may lead to legitimate routes being flagged as RPKI
      invalid.

      There are three options how to deal with unsafe VRPS:

      A policy of *reject* will filter out these VPRs. Warnings will be logged
      to indicate which VRPs have been filtered

      The *warn* policy will log warnings for unsafe VRPs but will add them to
      the valid VRPs.

      Finally, the *accept* policy will quietly add unsafe VRPs to the valid
      VRPs.

      Currently, the default policy is *warn* in order to gain operational
      experience with the frequency and impact of unsafe VRPs. This default may
      change in future version.

      For more information on the process of validation implemented in
      Routinator, see the section VALIDATION below.

.. option:: --unknown-objects=policy

      Defines how to deal with unknown types  of  RPKI  objects.  Currently,
      only certificates (.cer), CRLs (.crl), manifests (.mft), ROAs (.roa), and
      Ghostbuster  Records  (.gbr) are allowed to appear in the RPKI repository.

      There are, once more, three policies for dealing with an object of any
      other type:

      The *reject* policy will reject the object as well as the entire CA.
      Consequently, an unknown object appearing in a CA will mark all other
      objects issued by the CA as invalid as well.

      The policy of *warn* will log a warning, ignore the object, and accept all
      known objects issued by the CA.

      The  similar policy of *accept* will quietly ignore the object and accept
      all known objects issued by the CA.

      The default policy if the option is missing is *warn*.

      Note that even if unknown objects are accepted, they must appear in  the
      manifest and the hash over their content must match the one given in the
      manifest. If the hash does not  match, the CA and all its objects are
      still rejected.

.. option:: --allow-dubious-hosts

      As a precaution, Routinator will reject rsync and HTTPS URIs from RPKI
      data with dubious host names. In particular, it will reject the name
      *localhost*, host names that consist of IP addresses, and a host name that
      contains an explicit port.

      This option allows to disable this filtering.

.. option:: --disable-rsync

      If this option is present, rsync is disabled and only RRDP will be used.

.. option:: --rsync-command=command

      Provides the command to run for rsync. This is only the command itself. If
      you need to provide options to rsync, use the ``rsync-args``
      configuration file setting instead.

      If this option is not given, Routinator will simply run rsync and hope
      that it is in the path.

.. option:: --rsync-timeout=seconds

      Sets the number of seconds an rsync command is allowed to run before it
      is terminated early. This protects against hanging rsync commands that
      prevent Routinator from continuing. The default is 300 seconds which
      should be long enough except for very slow networks.

.. option:: --disable-rrdp

      If this option is present, RRDP is disabled and only rsync will be used.

.. option:: --rrdp-timeout=seconds

      Sets the timeout in seconds for any RRDP-related network operation, i.e.,
      connects, reads, and writes. If this option is omitted, the default
      timeout of 30 seconds is used. Set the option to 0 to disable the timeout.

.. option:: --rrdp-connect-timeout=seconds

      Sets the timeout in seconds for RRDP connect requests. If omitted, the
      general timeout will be used.

.. option:: --rrdp-local-addr=addr

      If present,  sets the local address that the RRDP client should bind to
      when doing outgoing requests.

.. option:: --rrdp-root-cert=path

      This option provides a path to a file that contains a certificate in PEM
      encoding that should be used as a trusted certificate for HTTPS server
      authentication. The option can be given more than once.

      Providing this option does not disable the set of regular HTTPS
      authentication trust certificates.

.. option:: --rrdp-proxy=uri

      This option provides the URI of a proxy to use for all HTTP connections
      made by the RRDP client. It can be either an HTTP or a SOCKS URI. The
      option can be given multiple times in which case proxies are tried in the
      given order.

.. option:: --dirty

      If this option is present, unused files and directories will not be
      deleted from the repository directory after each validation run.

.. option:: --validation-threads=count

      Sets the number of threads to distribute work to for validation. Note that
      the current processing model validates trust anchors all in one go, so you
      are likely to see less than that number of threads used throughout the
      validation run.

.. option:: -v, --verbose

      Print more information. If given twice, even more information is printed.

      More specifically, a single :option:`-v` increases the log level from the
      default of warn to info, specifying it more than once increases it to
      debug.

.. option:: -q, --quiet

      Print less information. Given twice, print nothing at all.

      A single :option:`-q` will drop the log level to error. Repeating
      :option:`-q` more than once turns logging off completely.

.. option:: --syslog

      Redirect logging output to syslog.

      This option is implied if a command is used that causes Routinator to run
      in daemon mode.

.. option:: --syslog-facility=facility

      If logging to syslog is used, this option can be used to specify the
      syslog facility to use. The default is daemon.

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

.. subcmd:: init

    Prepares the local repository directories and the TAL directory for running
    Routinator.  Specifically,  makes sure the local repository directory
    exists, and creates the TAL directory and fills it with the TALs of the five
    RIRs.

    For more information about TALs, see `Trust Anchor Locators`_ below.

    .. option:: -f, --force

           Forces installation of the TALs even if the TAL directory already
           exists.

    .. option:: --accept-arin-rpa

           Before you can use the ARIN TAL, you need to agree to the ARIN
           Relying Party Agreement (RPA). You can find it at
           https://www.arin.net/resources/manage/rpki/rpa.pdf and explicitly
           agree to it via this option. This explicit agreement is necessary in
           order to install the ARIN TAL.

    .. option:: --decline-arin-rpa

           If, after reading the ARIN Relying Party Agreement, you decide you do
           not or cannot agree to it, this option allows you to skip
           installation of the ARIN TAL. Note that this means Routinator will
           not have access to any information published for resources assigned
           under ARIN.


.. subcmd:: vrps

    This command requests that Routinator update the local repository and then
    validate the Route Origin Attestations in the repository and output the
    valid route origins, which are also known as Validated ROA Payload or VRPs,
    as a list.

    .. option:: -o file, --output=file

              Specifies the output file to write the list to. If this option
              is missing or file is - the list is printed to standard output.

    .. option:: -f format, --format=format

           The output format to use. Routinator currently supports the
           following formats:

           csv
                  The list is formatted as lines of comma-separated values of
                  the prefix in slash notation, the maximum prefix length,
                  the autonomous system number, and an abbreviation for the
                  trust anchor the entry is derived from. The latter is the
                  name of the TAL file without the extension *.tal*.

                  This is the default format used if the :option:`-f` option
                  is missing.

           csvcompat
                  The same as csv except that all fields are embedded in double
                  quotes and the autonomous system number is given without the
                  prefix AS. This format is pretty much identical to the CSV
                  produced by the RIPE NCC Validator.

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
                  The list is placed into a JSON object with a single
                  element *roas* which contains an array of objects with
                  four elements each:  The autonomous system number of the
                  network authorized to originate a prefix in *asn*, the
                  prefix in slash notation in *prefix*, the maximum prefix
                  length of the announced route in *maxLength*, and the
                  trust anchor from which the authorization was derived in
                  *ta*. This format is identical to that produced by the RIPE
                  NCC RPKI Validator except for different naming of the
                  trust anchor. Routinator uses the name of the TAL file
                  without the extension *.tal* whereas the RIPE NCC Validator
                  has a dedicated name for each.

           openbgpd
                  Choosing this format causes Routinator to produce a roa-
                  set configuration item for the OpenBGPD configuration.

           bird
                  Choosing this format causes Routinator to produce a roa table
                  configuration item for the BIRD configuration.

           bird2
                  Choosing this format causes Routinator to produce a roa table
                  configuration item for the BIRD2 configuration.

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

           If any of the rsync commands needed to update the repository failed,
           Routinator completes the operation and exits with status code 2.
           Normally, it would exit with status code 0 indicating success.

    .. option:: -a asn, --filter-asn=asn

           Only output VRPs for the given ASN. The option can be given multiple
           times, in which case VRPs for all provided ASNs are provided. ASNs
           can be given with or without the prefix AS.

    .. option:: -p prefix, --filter-prefix=prefix

           Only output VRPs with an address prefix that covers the given
           prefix, i.e., whose prefix is equal to or less specific than the
           given prefix. This will include VRPs regardless of their ASN and
           max length.  In other words, the output will include all VRPs
           that need to be considered when deciding whether an announcement
           for the prefix is RPKI valid or invalid.

           The option can be given multiple times, in which case VRPs for
           all prefixes are provided. It can also be combined with one or
           more ASN filters. Then all matching VRPs are included. That is,
           filters combine as "or" not "and."


.. subcmd:: validate

       This command can be used to perform RPKI route origin validation for a
       route announcement.  Routinator will determine whether the provided
       announcement is RPKI valid, invalid, or not found.

       .. option:: -a asn, --asn=asn

              The AS number of the autonomous system that originated the route
              announcement. ASNs can be given with or without the prefix AS.

       .. option:: -p prefix, --prefix=prefix

              The address prefix the route announcement is for.

       .. option:: -j, --json

              A detailed analysis on the reasoning behind the validation is
              printed in JSON format including lists of the VPRs that caused
              the particular result.   If this option is omitted, Routinator
              will only print the determined state.

       .. option:: -n, --noupdate

              The repository will not be updated before performing validation.

       .. option:: --complete

              If any of the rsync commands needed to update the repository
              failed, Routinator completes the operation and exits with status
              code 2. Normally, it would exit with status code 0 indicating
              success.


.. subcmd:: server

       This command causes Routinator to act as a server for the RPKI-to-Router
       (RTR) and HTTP protocols. In this mode, Routinator will read all
       the TALs (See `Trust Anchor Locators`_ below) and will stay attached to
       the terminal unless the :option:`-d` option is given.

       The server will periodically update the local repository, every ten
       minutes by default, notify any clients of changes, and let them fetch
       validated data. It will not, however, reread the trust anchor locators.
       Thus, if you update them, you will have to restart Routinator.

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

              Specifies a local address and port to listen on for incoming RTR
              connections.

              Routinator supports both protocol version 0 defined in :rfc:`6810`
              and version 1 defined in :rfc:`8210`. However, it does not support
              router keys introduced in version 1.  IPv6 addresses must be
              enclosed in square brackets. You can provide the option multiple
              times to let Routinator listen on multiple address-port pairs.

       .. option:: --http=addr:port

              Specifies the address and port to listen on for incoming HTTP
              connections.  See `HTTP Service`_ below for more information on
              the HTTP service provided by Routinator.

       .. option:: --listen-systemd

              The RTR listening socket will be acquired from systemd via socket
              activation. Use this option together with systemd's socket units
              to allow a Routinator running as a regular user to bind to the
              default RTR port 323.

              Currently, all TCP listener sockets handed over by systemd will
              be used for the RTR protocol.

       .. option:: --refresh=seconds

              The amount of seconds the server should wait after having finished
              updating and validating the local repository before starting to
              update again. The next update will be earlier if objects in the
              repository expire earlier. The default value is 600 seconds.

       .. option:: --retry=seconds

              The amount of seconds to suggest to an RTR client to wait before
              trying to request data again if that failed. The default value
              is 600 seconds, as recommended in :rfc:`8210`.

       .. option:: --expire=seconds

              The amount of seconds to an RTR client can keep using data if it
              cannot refresh it. After that time, the client should discard the
              data. Note that this value was introduced in version 1 of the RTR
              protocol and is thus not relevant for clients that only implement
              version 0. The default value, as recommended in :rfc:`8210`, is
              7200 seconds.

       .. option:: --history=count

              In RTR, a client can request to only receive the changes that
              happened since the last version of the data it had seen. This
              option sets how many change sets the server will at most keep. If
              a client requests changes from an older version, it will get the
              current full set.

              Note that routers typically stay connected with their RTR server
              and therefore really only ever need one single change set.
              Additionally, if RTR server or router are restarted, they will
              have a new session with new change sets and need to exchange a
              full data set, too. Thus, increasing the value probably only ever
              increases memory consumption.

              The default value is 10.

       .. option:: --pid-file=path

              States a file which will be used in daemon mode to store the
              processes PID.  While the process is running, it will keep the
              file locked.

       .. option:: --working-dir=path

              The working directory for the daemon process. In daemon mode,
              Routinator will change to this directory while detaching from the
              terminal.

       .. option:: --chroot=path

              The root directory for the daemon process. If this option is
              provided, the daemon process will change its root directory to the
              given directory. This will only work if all other paths provided
              via the configuration or command line options are under this
              directory.

       .. option:: --user=user-name

              The name of the user to change to for the daemon process. It this
              option is provided, Routinator will run as that user after the
              listening sockets for HTTP and RTR have been created. The option
              has no effect unless :option:`--detach` is also used.

       .. option:: --group=group-name

              The name of the group to change to for the daemon process.  It
              this option is provided, Routinator will run as that group after
              the listening sockets for HTTP and RTR have been created.  The
              option has no effect unless :option:`--detach` is also used.

.. subcmd:: update

       Updates the local repository by resyncing all known publication points.
       The command will also validate the updated repository to discover any
       new publication points that appear in the repository and fetch their
       data.

       As such, the command really is a shortcut for running
       :command:`routinator` :subcmd:`vrps` :option:`-f` ``none``.

       .. option:: --complete

              If any of the rsync commands needed to update the repository
              failed, Routinator completes the operation and exits with status
              code 2. Normally, it would exit with status code 0 indicating
              success.

.. subcmd:: man

       Displays the manual page, i.e., this page.

       .. option:: -o file, --output=file

              If this option is provided, the manual page will be written to the
              given file instead of displaying it. Use - to output the manual
              page to standard output.

Trust Anchor Locators
---------------------
RPKI uses trust anchor locators, or TALs, to identify the location and public
keys of the trusted root CA certificates. Routinator keeps these TALs in files
in the TAL directory which can be set by the  :option:`-t` option. If the
:option:`-b` option is used instead, the TAL directory will be in the
subdirectory *tals* under the directory specified in this option. The default
location, if no options are used at all is :file:`$HOME/.rpki-cache/tals`.

This directory can be created and populated with the TALs of the five Regional
Internet Registries (RIRs) via the :command:`init` command.

If the directory does exist, Routinator will use all files with an extension
of *.tal* in this directory. This means that you can add and remove trust
anchors by adding and removing files in this directory. If you add files, make
sure they are in the format described by :rfc:`7730` or the upcoming
:rfc:`8630`.

.. _doc_routinator_manpage_configfile:

Configuration File
------------------
Instead of providing all options on the command line, they can also be provided
through a configuration file. Such a file can be selected through the
:option:`-c` option. If no configuration file is specified this way but a file
named :file:`$HOME/.routinator.conf` is present, this file is used.

The configuration file is a file in TOML format. In short, it consists of a
sequence of key-value pairs, each on its own line. Strings are to be enclosed in
double quotes. Lists can be given by enclosing a comma-separated list of values
in square brackets.

The configuration file can contain the following entries. All path values are
interpreted relative to the directory the configuration file is located in. All
values can be overridden via the command line options.

repository-dir
      A string containing the path to the directory to store the local
      repository in. This entry is mandatory.

tal-dir
      A string containing the path to the directory that contains the Trust
      Anchor Locators. This entry is mandatory.

exceptions
      A list of strings, each containing the path to a file with local
      exceptions. If missing, no local exception files are used.

strict
      A boolean specifying whether strict validation should be employed. If
      missing, strict validation will not be used.

stale
      A string specifying the policy for dealing with stale objects.

      reject
             Consider all stale objects invalid rendering all material published
             by the CA issuing the stale object to be invalid including all
             material of any child CA.

      warn
             Consider stale objects to be valid but print a warning to the log.

      accept
             Quietly consider stale objects valid.

unsafe-vrps
      A string specifying the policy for dealing with unsafe VRPs.

      reject
             Filter unsafe VPRs and add warning messages to the log.

      warn
             Warn about unsafe VRPs in the log but add them to the final set of
             VRPs. This is the  default policy if the value is missing.

      accept
             Quietly add unsafe VRPs to the final set of VRPs.

unknown-objects
      A string specifying the policy for dealing with unknown RPKI object types.

       reject
             Reject the object and its issuing CA.

       warn
             Warn about the object but ignore it and accept the issuing CA.
             This is the default policy if the value is missing.

       accept
             Quietly ignore the object and accept the issuing CA.

allow-dubious-hosts
      A boolean value that, if present and true, disables Routinator's filtering
      of dubious host names in rsync and HTTPS URIs from RPKI data.

disable-rsync
      A boolean value that, if present and true, turns off the use of rsync.

rsync-command
      A string specifying the command to use for running rsync. The default is
      simply *rsync*.

rsync-args
      A list of strings containing the arguments to be passed to the rsync
      command. Each string is an argument of its own.

      If this option is not provided, Routinator will try to find out if your
      rsync understands the ``--contimeout`` option and, if so, will set it to
      10 thus letting connection attempts time out after ten seconds. If your
      rsync is too old to support this option, no arguments are used.

rsync-timeout
      An integer value specifying the number seconds an rsync command is allowed
      to run before it is being terminated. The default if the value is missing
      is 300 seconds.

disable-rrdp
      A boolean value that, if present and true, turns off the use of RRDP.

rrdp-timeout
      An integer value that provides a timeout in seconds for all individual
      RRDP-related network operations, i.e., connects, reads, and writes. If the
      value is missing, a default timeout of 30 seconds will be used. Set the
      value to 0 to turn the timeout off.

rrdp-connect-timeout
      An integer value that, if present, sets a separate timeout in seconds for
      RRDP connect requests only.

rrdp-local-addr
      A string value that provides the local address to be used by RRDP
      connections.

rrdp-root-certs
      A list of strings each providing a path to a file containing a trust
      anchor certificate for HTTPS authentication of RRDP connections. In
      addition to the certificates provided via this option, the system's own
      trust store is used.

rrdp-proxies
      A list of string each providing the URI for a proxy for outgoing RRDP
      connections. The proxies are tried in order for each request. HTTP and
      SOCKS5 proxies are supported.

dirty
      A boolean value which, if true, specifies that unused files and
      directories should not be deleted from the repository directory after each
      validation run.  If left out, its value will be false and unused files
      will be deleted.

validation-threads
      An integer value specifying the number of threads to be used during
      validation of the repository. If this value is missing, the number of CPUs
      in the system is used.

log-level
      A string value specifying the maximum log level for which log messages
      should be emitted. The default is warn.

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

      The default if this value is missing is, unsurprisingly, default.

log-file
      A string value containing the path to a file to which log messages will be
      appended if the log configuration value is set to file. In this case, the
      value is mandatory.

syslog-facility
      A string value specifying the syslog facility to use for logging to
      syslog. The default value if this entry is missing is daemon.

rtr-listen
      An array of string values each providing the address and port which the
      RTR daemon should listen on in TCP mode. Address and port should be
      separated by a colon. IPv6 address should be enclosed in square brackets.

http-listen
      An array of string values each providing the address and port which the
      HTTP service should listen on. Address and port should be separated by a
      colon. IPv6 address should be enclosed in square brackets.

listen-systemd
      The RTR TCP listening socket will be acquired from systemd via socket
      activation. Use this option together with systemd's socket units to allow
      Routinator running as a regular user to bind to the default RTR port
      323.

refresh
      An integer value specifying the number of seconds Routinator should wait
      between consecutive validation runs in server mode. The next validation
      run will happen earlier, if objects expire earlier. The default is 600
      seconds.

retry
      An integer value specifying the number of seconds an RTR client is
      requested to wait after it failed to receive a data set. The default is
      600 seconds.

expire
      An integer value specifying the number of seconds an RTR client is
      requested to use a data set if it cannot get an update before throwing it
      away and continuing with no data at all. The default is 7200 seconds if it
      cannot get an update before throwing it away and continuing with no data
      at all. The default is 7200 seconds.

history-size
      An integer value specifying how many change sets Routinator should keep in
      RTR server mode. The default is 10.

pid-file
      A string value containing a path pointing to the PID file to be used in
      daemon mode.

working-dir
      A string value containing a path to the working directory for the daemon
      process.

chroot
      A string value containing the path any daemon process should use as its
      root directory.

user
      A string value containing the user name a daemon process should run as.

group
      A string value containing the group name a daemon process should run as.

tal-label
      An array containing arrays of two string values mapping the name of a TAL
      file (without the path but including the extension) as given by the first
      string to the name of the TAL to be included where the TAL is referenced
      in output as given by the second string.

      If the options missing or if a TAL isn't mentioned in the option,
      Routinator will construct a name for the TAL by using its file name
      (without the path) and dropping the extension.

HTTP Service
------------
Routinator can provide an HTTP service allowing to fetch the Validated ROA
Payload in various formats. The service does not support HTTPS and should only
be used within the local network.

The service only supports GET requests with the following paths:

:command:`/metrics`
      Returns a set of monitoring metrics in the format used by Prometheus.

:command:`/status`
      Returns the current status of the Routinator instance. This is similar to
      the output of the **/metrics** endpoint but in a more human friendly
      format.

:command:`/log`
      Returns the logging output of the last validation run. The log level
      matches that set upon start.
      
      Note that the output is collected after each validation run and is
      therefore only available after the initial run has concluded.

:command:`/version`
      Returns the version of the Routinator instance.

:command:`/api/v1/validity/as-number/prefix`
      Returns a JSON object describing whether the route announcement given by
      its origin AS number and address prefix is RPKI valid, invalid, or not
      found.  The returned object is compatible with that provided by the RIPE
      NCC RPKI Validator. For more information, see
      https://ripe.net/support/documentation/developer-documentation/rpki-validator-api

:command:`/validity?asn=as-number&prefix=prefix`
      Same as above but with a more form-friendly calling convention.

In addition, the current set of VRPs is available for each output format
at a path with the same name as the output format. E.g., the CSV output is
available at ``/csv``.

These paths accept filter expressions to limit the VRPs returned in the form of
a query string. The field ``filter-asn`` can be used to filter for ASNs and the
field ``filter-prefix`` can be used to filter for prefixes. The fields can be
repeated multiple times.

This works in the same way as the options of the same name to the
:subcmd:`vrps` command.

Logging
-------
In order to allow diagnosis of the VRP data set as well as its overall health,
Routinator logs an extensive amount of information. The log levels used by
syslog are utilized to allow filtering this information for particular use
cases.

The log levels represent the following information:

error
      Information  related to events that prevent Routinator from continuing to
      operate at all as well as all issues related to local configuration even
      if Routinator will continue to run.

warn
      Information  about  events  and  data that influences the set of VRPs
      produced by Routinator. This includes failures to communicate with
      repository servers, or encountering invalid objects.

info
      Information about events and data that could be considered abnormal but do
      not influence the  set  of  VRPs  produced.  For example, when filtering
      of unsafe VRPs is disabled, the unsafe VRPs are logged with this level.

debug
      Information about the internal state of Routinator that may be useful for,
      well, debugging.

Validation
----------
      In :subcmd:`vrps` and :subcmd:`server` mode, Routinator will produce a set
      of VRPs from the data published in the RPKI repository. It will walk over
      all certfication authorities (CAs) starting with those referred to in the
      configured TALs.

      Each CA is checked whether all its published objects are present,
      correctly  encoded, and have been signed by the CA. If any of the objects
      fail this check, the entire CA will be rejected. If an object of an
      unknown  type  is encountered, the  behaviour depends on the
      ``unknown-objects`` policy. If this policy has a value of *reject* the
      entire CA will be rejected. In this case, only certificates (.cer), CRLs
      (.crl), manifestes (.mft), ROAs (.roa), and Ghostbuster records (.gbr)
      will be accepted.

      If  a CA is rejected, none of its ROAs will be added to the VRP set but
      also none of its child CAs will be considered at all; their published data
      will not be fetched or validated.

      If  a prefix has its ROAs published by different CAs, this will lead to
      some of its VRPs being dropped while others are still added. If the VRP
      for the  legitimately announced route is among those having been dropped,
      the route becomes RPKI invalid. This can happen both by operator error or
      through an active attack.

      In addition, if a VRP for a less specific prefix exists that covers the
      prefix of the dropped VRP, the route will be invalidated by the less
      specific VRP.

      Because  of  this  risk  of  accidentally  or  maliciously invalidating
      routes, VRPs that have address prefixes overlapping with resources of
      rejected CAs are called *unsafe VRPs*.

      In  order  to  avoid  these situations and instead fall back to an RPKI
      unknown state for such routes, Routinator allows to filter out these
      unsafe  VRPs. This can be enabled via the :option:`--unsafe-vrps=reject`
      command line option or setting :option:`unsafe-vrps=reject` in the config
      file.

      By default, this filter is currently disabled but warnings  are  logged
      about unsafe VPRs. This allows to assess the operation impact of such a
      filter. Depending on this assessment, the default may change in future
      version.

      One exception from this rule are CAs that have the full address space
      assigned, i.e., 0.0.0.0/0 and ::/0. Adding these to the filter would wipe
      out all VRPs. These prefixes are used by the RIR trust anchors to avoid
      having to update these often. However, each RIR has its own address space
      so losing all VRPs should something happen to a trust anchor is
      unnecessary.

Relaxed Decoding
----------------
The documents defining RPKI include a number of very strict rules regarding the
formatting of the objects published in the RPKI repository. However, because
RPKI reuses existing technology, real-world applications produce objects that
do not follow these strict requirements.

As a consequence, a significant portion of the RPKI repository is actually
invalid if the rules are followed. We therefore introduce two decoding
modes: strict and relaxed. Strict mode rejects any object that does not pass all
checks laid out by the relevant RFCs. Relaxed mode ignores a number of these
checks.

This memo documents the violations we encountered and are dealing with in
relaxed decoding mode.


   Resource Certificates (:rfc:`6487`)
       Resource certificates are defined as a profile on the more general
       Internet PKI certificates defined in :rfc:`5280`.


       Subject and Issuer
              The RFC restricts the type used for CommonName attributes to
              PrintableString,  allowing only a subset of ASCII characters,
              while :rfc:`5280` allows a number of additional string types. At
              least one CA produces resource certificates with Utf8Strings.

              In relaxed mode, we will only check that the general structure of
              the issuer and subject fields are correct and allow any number and
              types of attributes. This seems justified since RPKI explicitly
              does not use these fields.

   Signed Objects (:rfc:`6488`)
       Signed objects are defined as a profile on CMS messages defined in
       :rfc:`5652`.

       DER Encoding
              :rfc:`6488` demands all signed objects to be DER encoded while the
              more general CMS format allows any BER encoding  --  DER is a
              stricter subset of the more general BER. At least one CA does
              indeed produce BER encoded signed objects.

              In relaxed mode, we will allow BER encoding.

              Note that this isn't just nit-picking. In BER encoding, octet
              strings can be broken up into a sequence of sub-strings. Since
              those strings are in some places used to carry encoded content
              themselves, such an encoding does make parsing significantly more
              difficult. At least one CA does produce such broken-up strings.

Signals
-------
SIGUSR1: Reload TALs and restart validation
   When receiving SIGUSR1, Routinator will attempt to reload the TALs and, if
   that succeeds, restart validation. If loading the TALs fails, Routinator will
   exit.

Exit Status
-----------
Upon success, the exit status 0 is returned. If any fatal error happens, the
exit status will be 1. Some commands provide a :option:`--complete` option which
will cause the exit status to be 2 if any of the rsync commands to update the
repository fail.
