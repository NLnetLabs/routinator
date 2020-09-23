# Change Log

# Unreleased Next Version

Breaking Changes

* Validation now follows the rules suggested by
  [draft-ietf-sidrops-6486bis]\: Any invalid object mentioned on the
  manifest will lead to the issuing CA and all its objects being rejected.
  However, unlike suggested by the draft, Routinator currently will not fall
  back to cached older versions of the CA’s objects that may still be valid.
  ([#371])
* All VRPs overlapping with resources from rejected CAs are filtered. This
  will avoid situations were routes become RPKI invalid if their VRPs are
  split over multiple CAs or there are less specific ROAs. ([#377])
* Parsing of local exception files is now more strict in accordance with
  [RFC 8416]. Any additional member in the JSON objects will lead to an
  error. However, error reporting has been greatly improved and now the
  line and column of an error will be indicated. ([#372])
* The alias `--allow-dubios-hosts` for the correctly spelled option has
  been removed. ([#384])
* The minimal supported Rust version is now 1.42.0.

New

* New metrics for the VRPs produced and filtered on the various TALs.
  ([#377])
* The feature `rta` enables the new command `rta` for validating Resource
  Tagged Assertions as described in [draft-michaelson-rpki-rta]. This
  feature is not enabled by default and needs to be activated by adding
  the option `--features rta` to the Cargo build command.

* Irrelevant log messages from libraries are now also filtered when using
  syslog logging. ([#385])

Bug Fixes


Dependencies

Other Changes

[#357]: https://github.com/NLnetLabs/routinator/pull/357
[#371]: https://github.com/NLnetLabs/routinator/pull/371
[#372]: https://github.com/NLnetLabs/routinator/pull/372
[#377]: https://github.com/NLnetLabs/routinator/pull/377
[#384]: https://github.com/NLnetLabs/routinator/pull/384
[#385]: https://github.com/NLnetLabs/routinator/pull/385
[RFC 8416]: https://tools.ietf.org/html/rfc8416
[draft-ietf-sidrops-6486bis]: https://datatracker.ietf.org/doc/draft-ietf-sidrops-6486bis/
[draft-michaelson-rpki-rta]: https://datatracker.ietf.org/doc/html/draft-michaelson-rpki-rta


# 0.7.1 ‘Moonlight and Love Songs’

Release 2020-06-15.

There have been no changes since RC2.


# 0.7.1-rc2

Released 2020-06-10.

Other Changes

* Update the ARIN TAL to include the HTTPS URIs of their trust anchor
  certificate. ([#347])

[#347]: https://github.com/NLnetLabs/routinator/pull/347


## 0.7.1-rc1

Released 2020-06-09.

New

* The HTTP `/status` command now contains a `version` field showing the
  Routinator version running. [(#342)]

Bug Fixes

* Prefer HTTPS URIs in TALs if RRDP is enabled. The order of URIs with the
  same scheme is maintained. ([#343])
* Fix a typo in the `--allow-dubious-hosts` option which was actually
  expected to be spelled as `--allow-dubios-hosts`. This dubious spelling
  is kept as an alias until the next breaking release. ([#339])

Dependencies

* Remove the pin on Tokio and set the minimum version to 0.2.21. ([#340])

Other Changes

* Update the AFRINIC, APNIC and RIPE NCC TALs to include HTTPS URIs for
  their trust anchor certificates. ([#331], [#344], [#345])

[#331]: https://github.com/NLnetLabs/routinator/pull/331
[#339]: https://github.com/NLnetLabs/routinator/pull/339
[#340]: https://github.com/NLnetLabs/routinator/pull/340
[#342]: https://github.com/NLnetLabs/routinator/pull/342
[#343]: https://github.com/NLnetLabs/routinator/pull/343
[#344]: https://github.com/NLnetLabs/routinator/pull/344
[#345]: https://github.com/NLnetLabs/routinator/pull/345


## 0.7.0 ‘Your Time Starts … Now’

Released 2020-05-06.

There have been no changes since RC3.


## 0.7.0-rc3

Dependencies

* Pinned Tokio to 0.2.13. There have been reports of issues with automatic
  cooperative task yielding introduced in 0.2.14, so we will stick with
  0.2.13 for this release. ([#321])

[#321]: https://github.com/NLnetLabs/routinator/pull/321


## 0.7.0-rc2

Bug Fixes

* Bind listening sockets before possibly dropping privileges while
  detaching. ([#313], discovered by [@alarig]).
* Re-enable Tokio’s threaded runtime. ([#315])

[#313]: https://github.com/NLnetLabs/routinator/pull/313
[#315]: https://github.com/NLnetLabs/routinator/pull/315
[@alarig]: https://github.com/alarig


## 0.7.0-rc1

Breaking Changes

* Routinator now filters out rsync URIs and RRDP URIs that contain dubious
  host names that should not be present in the public RPKI. In this
  version they are ‘localhost,’ any IP address, and any URI with the port
  explicitly specified. This filter can be disabled via the
  `--allow-dubious-hosts` command line and config option for test
  deployments. ([#293])
* Only CRLs mentioned on the manifest are now considered when checking any
  published objects except for the manifest itself. If the hash of the CRL
  on the manifest does not match the CRL, it is rejected. Objects
  referencing a CRL that is not on a manifest or has a hash mismatch are
  rejected. [(#299)]
* The minimal supported Rust version is now 1.39.0.

New

* The new option `--stale` allows selecting a policy for dealing with
  stale objects – i.e., manifests and CRLs that are past their
  *next-update* date. The policies are `reject`, `warn`, and `accept`. The
  previous hard-coded policy of `warn`, i.e., accept but log a warning, is
  the default. ([#288])
* New output formats `bird` and `bird2` which produce a `roa table` for
  Bird 1 and a `route table` for Bird 2, respectively. ([#290], by
  [@netravnen])
* New output format `csvcompat` which produces CSV output as similar to
  that of the RIPE NCC Validator as possible. ([#292])
* The new config file option `tal-labels` allows defining explicit names
  to be used when TALs are referenced in output. This way, the output can
  be made to be even more similar to that produced by the RIPE NCC
  Validator. ([#291])
* The _csvext_ output format is now also available via the HTTP server at
  the `/csvext` path. ([#294])
* New metrics for the status of the RTR and HTTP servers. ([#298])
* New metric of the number of stale objects encountered in the last
  validation run. ([#298])

Other Changes

* Update to Rust’s new asynchronous IO framework for the RTR and HTTP
  servers. Repository synchronization and validation remain synchronous
  atop a thread pool. ([#282])
* Changed concurrency strategy for repository update and validation.
  Previously, each trust anchor was updated and validated synchronously.
  Now processing of a CA is deferred if its repository publication point
  hasn’t been updated yet. Processing is then picked up by the next
  available worker thread. This should guarantee that all worker threads
  are busy all the time. ([#284)]
* Optimized what information to keep for each ROA, bringing maximum memory 
  consumption down to about a quarter. ([#293])
* The Docker image now wraps Routinator into [tini] for properly dealing
  with signals and child processes. ([#277])

[#277]: https://github.com/NLnetLabs/routinator/pull/277
[#282]: https://github.com/NLnetLabs/routinator/pull/282
[#284]: https://github.com/NLnetLabs/routinator/pull/284
[#288]: https://github.com/NLnetLabs/routinator/pull/288
[#290]: https://github.com/NLnetLabs/routinator/pull/290
[#291]: https://github.com/NLnetLabs/routinator/pull/291
[#292]: https://github.com/NLnetLabs/routinator/pull/292
[#293]: https://github.com/NLnetLabs/routinator/pull/293
[#294]: https://github.com/NLnetLabs/routinator/pull/294
[#298]: https://github.com/NLnetLabs/routinator/pull/298
[#299]: https://github.com/NLnetLabs/routinator/pull/299
[@netravnen]: https://github.com/netravnen
[tini]: https://github.com/krallin/tini


## 0.6.4 ‘Jeepers’

Bug Fixes

* Fixes an issue where Routinator occasionally gets completely stuck.
  [(#255)]

[(#255)]: https://github.com/NLnetLabs/routinator/pull/255


## 0.6.3 ‘That Escalated Fast’

New

* Reload TALs and restart validation via SIGUSR1 on Unix systems.
  ([#241], thanks to [Veit Heller]!)

Bug Fixes

* RRDP requests failed with a timeout if Routinator was started in
  detached server mode (`server -d`). ([#250], discovered by [Will McLendon])
* Fix spelling of `routinator_rrdp_duration` metrics definition. [(#248)]

[#241]: https://github.com/NLnetLabs/routinator/pull/241
[(#248)]: https://github.com/NLnetLabs/routinator/pull/248
[#250]: https://github.com/NLnetLabs/routinator/pull/250
[Will McLendon]: https://github.com/wmclendon
[Veit Heller]: https://github.com/hellerve


## 0.6.2 ‘Distiller’s Edition’

New

* Added a `--disable-rsync` command line and `disable-rsync` configuration
  file option to, well, disable rsync. [(#229)]

Bug Fixes

* Fall back to rsync data if RRDP data is missing in no-update mode.
  (This only caused trouble if you are fabricating a repository cache
  directory from rsync-only data.) [(#223)]
* Try creating the parent directories before moving a file published via
  RRDP delta to its final location. This avoids regular fallback to
  snapshots. [(#227)]
* Consider previously manipulated files when processing a sequence of
  multiple RRDP deltas. This avoids occasional fallback to snapshots.
  [(#228)]
* Fixed a decoding error in manifests which caused certain manifests (which
  don’t seem to be existing in the wild currently) to be rejected.
  [(via rpki-rs #78)]
* The `/rpsl` endpoint of the HTTP server accidentally produced CSV
  output. [(#238)]
* Produce a formatting of the time elements of RPSL with a stable length.
  This will result in the RPSL output via the HTTP server to be correct
  and also decreases the size of the RPSL output by about twenty percent.
  [(#243)]

Other Changes

* Suppressing debug log from some dependencies for stderr and file
  logging. [(#224)]

[(#223)]: https://github.com/NLnetLabs/routinator/pull/223
[(#224)]: https://github.com/NLnetLabs/routinator/pull/224
[(#227)]: https://github.com/NLnetLabs/routinator/pull/227
[(#228)]: https://github.com/NLnetLabs/routinator/pull/228
[(via rpki-rs #78)]: https://github.com/NLnetLabs/rpki-rs/pull/78
[(#229)]: https://github.com/NLnetLabs/routinator/pull/229
[(#238)]: https://github.com/NLnetLabs/routinator/pull/238
[(#243)]: https://github.com/NLnetLabs/routinator/pull/243


## 0.6.1 ‘Philosophy Is Tricky’

New

* RRDP access statistics are now also shown in the `/status` HTTP
  endpoint. They were already part of the Prometheus metrics. [(#218)]

Bug Fixes

* The RTR serial number was not increased when new data became available.
  [(#215)]

Other changes

* The RRDP client will not complain if it can’t read a non-existing state
  file anymore as this is a completely normal situation. [(#217)]


Dependencies

[(#215)]: https://github.com/NLnetLabs/routinator/pull/215
[(#217)]: https://github.com/NLnetLabs/routinator/pull/217
[(#218)]: https://github.com/NLnetLabs/routinator/pull/218


## 0.6.0 ‘Pink Sombrero’

Breaking Changes

* Removed the `rsync-count` command line and configuration file option.
  This option is now unused as modules are now rsynced only when they are
  actually accessed. [(#187)]
* The default value for `refresh` has been lowered to 600 seconds.
  [(#191)]
* The refresh time placed in the RTR End-of-data PDU is now calculated
  from the time until the next validation run is expected to finish.
  [(#193)]
* The listeners for RTR and HTTP in server mode are now started right away
  and report an error until the first validation has finished. [(#203)]

New

* Routinator now supports RRDP for synchronizing repository content.
  [(#187)]
* Restructured repository directory. The rsync data now lives in a
  sub-directory called `rsync`. The main repository directory will now be
  kept clean and all unexpected files removed. [(#187)]
* In server mode, the repository will be refreshed and re-validated when
  the first object expires. [(#191)]
* Protection against loops in the CA structure: Routinator checks that any
  subject key identifier only appears once in the chain from a trust
  anchor to a CA certificate. [(#192)]
* Routinator now explicitly skips .cer files that aren’t CA certificates
  before even trying to validate them. This already happened before
  because these files failed validation. [(#194)]
* New options `user` and `group` for setting the user and group names a
  detached server process should be run as. [(#213)]

Bug Fixes

* Fixed crash if the TAL directory is empty. Routinator will complain but
  run since there could be local exceptions. [(#212)]

[(#187)]: https://github.com/NLnetLabs/routinator/pull/187
[(#191)]: https://github.com/NLnetLabs/routinator/pull/191
[(#192)]: https://github.com/NLnetLabs/routinator/pull/192
[(#193)]: https://github.com/NLnetLabs/routinator/pull/193
[(#194)]: https://github.com/NLnetLabs/routinator/pull/194
[(#203)]: https://github.com/NLnetLabs/routinator/pull/203
[(#212)]: https://github.com/NLnetLabs/routinator/pull/212
[(#213)]: https://github.com/NLnetLabs/routinator/pull/213


## 0.5.0 ‘Why Not Try a Holiday in Sweden This Year?’

Breaking Changes

* Prometheus metrics are now prefixed with `routinator_`. ([#162] by
  [@momorientes])
* Added `--timeout` option to `rsync` call. This seems to be available on
  most rsync versions in use. Should that not be the case, you can use
  the `rsync-args` config file option to define your own set of rsync
  arguments, overriding this behaviour. ([#176])

New

* The local copy of the repository is now cleaned up after each validation
  run, removing directories and files that weren’t referenced during the
  run. This can be disabled with the new `--dirty` command line and
  `dirty` config file options. [(#180)]
* You can now check pairs of address prefix and AS number for their RPKI
  origin validation status either via the HTTP interface or the new `validate`
  command. The HTTP API is the same as that used by the RIPE NCC RPKI
  Validator for easy migration. [(#173)]
* Output format `summary` which will print a summary of the content of the
  RPKI repository. [(#167)]
* The ARIN TAL can now be skipped during `init` with the `--decline-arin-rpa`
  option. [(#169)]
* Various commands have received a `--complete` option that causes them to
  exit with status code 2 if any of the rsync commands fails. ([#177)]
* Additional metrics showing the status and duration of rsync commands.
  [(#178)]

Bug Fixes

* Fix Prometheus metrics output – Prometheus insists on a line break at the
  end of the last line. [(#156)]
* Fix Prometheus metrics definitions. ([#161] by [@momorientes])
* The HTTP server can now deal with unreasonably large requests. It has
  been switched to using [hyper]. [(#171)]

[(#156)]: https://github.com/NLnetLabs/routinator/pull/156
[#161]: https://github.com/NLnetLabs/routinator/pull/161
[#162]: https://github.com/NLnetLabs/routinator/pull/162
[@momorientes]: https://github.com/momorientes
[(#167)]: https://github.com/NLnetLabs/routinator/pull/167
[(#169)]: https://github.com/NLnetLabs/routinator/pull/169
[(#171)]: https://github.com/NLnetLabs/routinator/pull/171
[hyper]: https://hyper.rs/
[(#173)]: https://github.com/NLnetLabs/routinator/pull/173
[(#176)]: https://github.com/NLnetLabs/routinator/pull/176
[(#177)]: https://github.com/NLnetLabs/routinator/pull/177
[(#178)]: https://github.com/NLnetLabs/routinator/pull/178
[(#180)]: https://github.com/NLnetLabs/routinator/pull/180


## 0.4.0 ‘The Bumpy Road to Love’

Breaking Changes

* Major cleanup of the command line and configuration file for server
  mode. The command is now `server` (instead of `rtrd`). RTR and HTTP are
  now equals. There is no more default listeners being created, you have to
  specify them explicitly via command line options or config file. The option
  is now `--rtr` for RTR listeners (previously just `--listen`) and
  `--http` for HTTP listeners (previously `--listen-http`). The config
  file fields are `rtr-listen` and `http-listen`, respectively. [(#133)]
* In `server` (formerly `rtrd`) mode, the `-a` option is gone and has
  been replaced by a `-d` option. In other words, the default is now to
  stay attached to the terminal and only fork into the background if `-d`
  is given. [(#134)]
* The TAL directory will no longer be automatically populated. Instead,
  you can install the bundled TALs via the new `init` command.  After
  having received permission from ARIN, we are now also bundling the ARIN
  TAL in Routinator and require specific agreement to ARIN’s Relying Party
  Agreement via a command line option. [(#135)]
* The minimum supported Rust version is now 1.34.0. [(#112)]

New

* Four new monitoring gauges `last_update_start`, `last_update_done`, 
  `last_update_duration`, and `serial` that will allow alerting if
  Routinator stops updating. ([#122] and [#131])
* Accept RTR listening socket from systemd. This allows to listen on port
  323 without special privileges. Enable via the new `--listen-systemd`
  option. ([#127] and [#130]).
* Improved path `/status` in HTTP output that provides the same
  information as the `/metrics` endpoint in slightly different format that
  might make it easier to use in processing. [(#131)]
* Filtering for address prefixes and ASNs in VRP output via the `vrps`
  command or in HTTP output. [(#137)]

Bug Fixes

* The value of the `listen-http` config option wasn’t include in the
  output of the `config` command. Now it is. [(#109)]
* The HTTP server would eventually hang Routinator in a tight loop if
  connections were closed early by the peer. [(#120)]
* Only read files ending in `.tal` in the TAL directory as is already
  documented. [(#121)]
* Announce the correct content type in HTTP output with formats JSON and
  CSV. [(#146)]

Dependencies

* Update to rpki-rs 0.4 [(#111)]

[(#109)]: https://github.com/NLnetLabs/routinator/pull/109
[(#111)]: https://github.com/NLnetLabs/routinator/pull/111
[(#112)]: https://github.com/NLnetLabs/routinator/pull/112
[(#120)]: https://github.com/NLnetLabs/routinator/pull/120
[(#121)]: https://github.com/NLnetLabs/routinator/pull/121
[#122]: https://github.com/NLnetLabs/routinator/pull/122
[#127]: https://github.com/NLnetLabs/routinator/pull/127
[#130]: https://github.com/NLnetLabs/routinator/pull/130
[(#131)]: https://github.com/NLnetLabs/routinator/pull/131
[#131]: https://github.com/NLnetLabs/routinator/pull/131
[(#133)]: https://github.com/NLnetLabs/routinator/pull/133
[(#134)]: https://github.com/NLnetLabs/routinator/pull/134
[(#135)]: https://github.com/NLnetLabs/routinator/pull/135
[(#137)]: https://github.com/NLnetLabs/routinator/pull/137
[(#146)]: https://github.com/NLnetLabs/routinator/pull/146


## 0.3.3 ‘Big Bada Boom’

Bug Fixes

* The config file option specific to `rtrd` mode weren’t picked up.
  ([#102], reported by Jay Borkenhagen)
* Ignore ‘broken pipe’ errors when outputting VRPs to make Routinator play
  nice with piping output into scripts etc. [(#105)]
* Fixes a crash when validating certain invalid resource sets on
  certificates. [(rpki-rs #30)]

Dependencies

* There’s now a crude way to check if you have the minimum Rust version
  required and stop building. [(#104)]

[#102]: https://github.com/NLnetLabs/routinator/pull/102
[(#104)]: https://github.com/NLnetLabs/routinator/pull/104
[(#105)]: https://github.com/NLnetLabs/routinator/pull/105
[(rpki-rs #30)]: https://github.com/NLnetLabs/rpki-rs/pull/30


## 0.3.2 ‘Bitter and Twisted’

Bug Fixes

* Print errors when reading the trust anchor locators to standard error
  instead of logging them since logging isn’t set up yet at that point.
  [(#89)]
* Use `route6:` fields in RPSL output for IPv6 prefixes. ([#96], reported
  by [@matsm])
* Use LF as line endings in RPSL output. Seems that’s what whois uses in
  practice, too. ([#97], reported by [@matsm])

[(#89)]: https://github.com/NLnetLabs/routinator/pull/89
[#96]: https://github.com/NLnetLabs/routinator/pull/96
[#97]: https://github.com/NLnetLabs/routinator/pull/97
[@matsm]: https://github.com/matsm


## 0.3.1 ‘More Intensity’

New

* TAL files will only be read once when Routinator starts. This
  improves robustness at the cost of having to restart Routinator when the
  TALs change. [(#74)]
* New option `--rsync-timeout` setting the maximum number of seconds any
  rsync command is allowed to run. This prevents hanging rsync from
  blocking Routinator. [(#76)]
* Additional Prometheus metric `valid_roas` reporting the number of
  verified ROAs. Additionally, both metrics are now reported separately
  for each TAL. [(#78)]
* Compare RTR serial numbers according to RFC 1932. [(#81)]

Bug Fixes

* A missing `tcp-listen` option in the config file caused Routinator to
  crash in `rtrd` mode instead of using the default socket. [(#80)]
* Decoding manifest and ROAs now checks that the content type field in the
  signed object has the correct object identifier. [(rpki-rs #27)]

[(#74)]: https://github.com/NLnetLabs/routinator/pull/74
[(#76)]: https://github.com/NLnetLabs/routinator/pull/76
[(#78)]: https://github.com/NLnetLabs/routinator/pull/78
[(#80)]: https://github.com/NLnetLabs/routinator/pull/80
[(#81)]: https://github.com/NLnetLabs/routinator/pull/81
[(rpki-rs #27)]: https://github.com/NLnetLabs/rpki-rs/pull/27


## 0.3.0 ‘It’s More Fun at the Zoo’

Breaking Changes

* Several API and organizational changes in the Routinator library crate
  for the various improvements below.

New

* New output format `csvext` that mimics the output format of the Original
  RIPE NCC Validator. [(#59)]

* Support for alternative resource extensions and validation defined in
  [RFC 8360]. (The accompanying changes made it quite a bit faster, too.)
  [(#63)]

* Support for [cargo-deb]-based Debian packaging. Thanks to David
  Monosov. [(#62)]

* Log warnings for stale manifests and CRLs.

* Optional HTTP service in `rtrd` mode. This can be enabled via the
  `--listen-http` command line option and the `listen-http` config option.
  This is only the beginning of more extensive monitoring support. [(#68)]

Bug Fixes

* Converts the endianess of the serial number in the SerialNotify RTR PDU.
  Reported by Massimiliano Stucchi. [(#60)]

Dependencies

* Docker build updated to Rust 1.32 and Alpine Linux 3.9. Thanks to David
  Monosov. [(#61)]

Housekeeping

* Included [Clippy] in Travis runs for better code quality. [(#65)]


[(#59)]: https://github.com/NLnetLabs/routinator/pull/59
[(#60)]: https://github.com/NLnetLabs/routinator/pull/60
[(#61)]: https://github.com/NLnetLabs/routinator/pull/61
[(#62)]: https://github.com/NLnetLabs/routinator/pull/62
[(#63)]: https://github.com/NLnetLabs/routinator/pull/63
[(#65)]: https://github.com/NLnetLabs/routinator/pull/65
[(#68)]: https://github.com/NLnetLabs/routinator/pull/68
[Clippy]: https://github.com/rust-lang/rust-clippy
[cargo-deb]: https://github.com/mmstick/cargo-deb


## 0.2.1 ‘Rated R’

New

* The `config` command now prints the configuration in TOML format and
  can be used to create a configuration file for the current
  configuration. [(#54)]
* Routinator now builds and runs on Windows. Given that Windows is a Rust
  tier 1 platform, we wanted to see how difficult it is to get this
  going. Note that you will need the `rsync` executable that comes with
  [Cygwin](https://www.cygwin.com/). [(#55)]

Bug Fixes

* Actually use `$HOME/.routinator.conf` as the default config file as
  promised by the documentation. [(#49)]
* Fix a compile time error on 32 bit systems.

[(#49)]: https://github.com/NLnetLabs/routinator/pull/49
[(#54)]: https://github.com/NLnetLabs/routinator/pull/54
[(#55)]: https://github.com/NLnetLabs/routinator/pull/55

## 0.2.0 ‘Instant Gezellig’

Breaking Changes

* The command line arguments have been restructured to use commands to
  determine the mode of operation rather than options. In the course of
  that, some options changed, too. [(#35)]
* Add trust anchor information to the CSV, JSON, and RPSL output. [(#21)]

New

* Add a configuration file for all standard options and the options for
  the RTR server mode. [(#35)]
* Add a `Dockerfile` for building and deploying through Docker. Thanks to
  David Monosov. [(#23)]
* Output from the rsync runs is now send to the logger and will be handled
  according to log settings. Output to stderr is logged with log level
  _warn,_ stdout is logged with _info._ [(#27)]
* New options for daemon mode: `pid-file`, `working-dir`, and `chroot`.
  Options to change the user and group in daemon mode are coming soon.
  [(#42)]
* In daemon mode, forking now happens _after_ the TALs are checked so that
  you can see the error messages and that it fails.
* New VRP output format `openbgpd` which produces a `roa-set` for
  [OpenBGPD](http://www.openbgpd.org/) config.
  Thanks to Job Snijders. [(#32)]
* A new command line and config file option `rsync-command` allows to
  choose which command to run for rsync. A new config file option
  `rsync-args` allows to provide arguments to rsync. [(#41)]

Bug Fixes

* The default output format was accidentally changed to `none`. It is
  `csv` again.

Performance Improvements

* Caching of CRL serial numbers for CAs with large manifests leads to
  about half the validation time for the current repository. [(#34)]

[(#21)]: https://github.com/NLnetLabs/routinator/pull/21
[(#23)]: https://github.com/NLnetLabs/routinator/pull/23
[(#27)]: https://github.com/NLnetLabs/routinator/pull/27
[(#32)]: https://github.com/NLnetLabs/routinator/pull/32
[(#34)]: https://github.com/NLnetLabs/routinator/pull/34
[(#35)]: https://github.com/NLnetLabs/routinator/pull/35
[(#41)]: https://github.com/NLnetLabs/routinator/pull/41
[(#42)]: https://github.com/NLnetLabs/routinator/pull/42

## 0.1.2 ‘And I Cry If I Want To’

Bug Fixes

* [Panic in iterating over the withdrawals in an RTR set][17].
* When comparing serial numbers for RTR Serial Query, looked at the oldest
  known serial not the newest, always returning an empty change set.

[17]: https://github.com/NLnetLabs/routinator/issues/17

## 0.1.1 ‘Five-second Rule’

Bug Fixes

* [Wrong End Of Data PDU in RPKI-RTR version 0.][15]

[15]: https://github.com/NLnetLabs/routinator/issues/15

## 0.1.0 ‘Godspeed!’

Initial public release.
