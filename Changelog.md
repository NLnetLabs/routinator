# Change Log

# Unreleased future version

Breaking Changes

* The minimal supported Rust version is now 1.52. ([#681])

Bug Fixes

* Encountering stray files at the top level of the rsync cache directory
  will not cause Routinator to exit any more. Instead, it will just delete
  those files. ([#675])
* Don’t exit when a directory to be deleted doesn’t exist. In particular,
  this fixes an error in the `dump` command. ([#682])
* Counts all valid CRLs during a validation run. ([#683])

New

* Add TLS support to the RTR and HTTP servers. ([#677])
* Reject so-called premature manifests, i.e., manifests that have an issue
  time before the current time. This is a new requirement in
  [draft-ietf-sidrops-6486bis]. ([#681])

Other Changes

* Update the NLnet Labs RPKI testbed TAL to the one used by the new
  server. ([#637])

[#637]: https://github.com/NLnetLabs/routinator/pull/637
[#675]: https://github.com/NLnetLabs/routinator/pull/675
[#677]: https://github.com/NLnetLabs/routinator/pull/677
[#681]: https://github.com/NLnetLabs/routinator/pull/681
[#682]: https://github.com/NLnetLabs/routinator/pull/682
[#683]: https://github.com/NLnetLabs/routinator/pull/683
[draft-ietf-sidrops-6486bis]: https://datatracker.ietf.org/doc/draft-ietf-sidrops-6486bis/


# 0.10.2 ‘Skuffet, men ikke overrasket’

Released 2021-11-09.

Bug Fixes

* The `rrdp-timeout` configuration setting now correctly limits the maximum
  length an RRDP request can take. This prevents a possible issue where a
  RRDP repository maliciously or erroneously delays a request and
  subsequently a validation run. ([#666], [CVE-2021-43173])

New

* The new configuration setting `max-ca-depth` limits the length a chain
  of CAs from a trust anchor. By default it is set to 32. This fixes a
  possible vulnerability where a CA creates an infinite chain of CAs.
  ([#665], [CVE-2021-43172])

Other Changes

* Support for the gzip transfer encoding for RRDP has been removed because
  gzip in combination with XML provides multiple ways to delay validation.
  The configuration setting `rrdp-disable-gzip` is now deprecated and will
  be removed in the next breaking release. ([#667], [CVE-2021-43174])

[#665]: https://github.com/NLnetLabs/routinator/pull/665
[#666]: https://github.com/NLnetLabs/routinator/pull/666
[#667]: https://github.com/NLnetLabs/routinator/pull/667
[CVE-2021-43172]: https://www.nlnetlabs.nl/downloads/routinator/CVE-2021-43172_CVE-2021-43173_CVE-2021-43174.txt
[CVE-2021-43173]: https://www.nlnetlabs.nl/downloads/routinator/CVE-2021-43172_CVE-2021-43173_CVE-2021-43174.txt
[CVE-2021-43174]: https://www.nlnetlabs.nl/downloads/routinator/CVE-2021-43172_CVE-2021-43173_CVE-2021-43174.txt


## 0.10.1 ‘That’s No Moon’

Released 2021-09-20.

No changes since 0.10.1-rc3.


## 0.10.1-rc3

Released 2021-09-15.

Other Changes

* Update UI to 0.3.4. ([#651]) 
  * Fixed links for prefixes.

[#651]: https://github.com/NLnetLabs/routinator/pull/651


## 0.10.1-rc2

Released 2021-09-13.

Bug Fixes

* Redirect `/` to `/ui` to bring back the UI for the blank hostname.
  ([#648])

Other Changes

* Update UI to 0.3.3.
  * Fixes UI loading with query parameters.

[#648]: https://github.com/NLnetLabs/routinator/pull/648


## 0.10.1-rc1

Released 2021-09-13.

Other Changes

* Extended UI with BGP and allocation data lookups. ([#635])
* The UI now lives in its own crate [routinator-ui]. ([#635])

[#635]: https://github.com/NLnetLabs/routinator/pull/635
[routinator-ui]: https://crates.io/crates/routinator-ui


## 0.10.0 ‘Through Many Dangers, Toils, and Snares’

Released 2021-08-23

No changes since 0.10.0-rc3.


## 0.10.0-rc3

Released 2021-08-02.

New

* Strict checking for address and prefix lengths in certificates, and for
  prefix and max-length in ROAs. (via [rpki #154], based on an error report by
  [@job])

[rpki #154]: https://github.com/NLnetLabs/rpki-rs/pull/154
[@job]: https://github.com/job


## 0.10.0-rc2

Released 2021-07-27.

Bug Fixes

* Fix the missing line feed in the summary output format. ([#625])
* The RTR server now returns the correct PDU as a cache reset response,
  which is returned when the server cannot provide a delta update to a
  client. Previously, a broken End of Data PDU was returned.
  (Via [rpki #151].)
* Make parsing of local exception files much more strict to avoid introducing
  illegal VRPs into the data set. Parsing will now fail if any aspect of a
  prefix or prefix assertion is incorrect. This includes a non-zero host
  portion of a prefix. ([#627])

[#625]: https://github.com/NLnetLabs/routinator/pull/625
[#627]: https://github.com/NLnetLabs/routinator/pull/627
[rpki #151]: https://github.com/NLnetLabs/rpki-rs/pull/151


## 0.10.0-rc1

Released 2021-07-23.

Breaking changes

* Data is now stored directly in the file system again. This returns
  memory consumption to pre-0.9 levels. All improvements to robustness
  have been maintained. ([#590], [#601], [#604])
* The `json` and `jsonext` output formats now include a `metadata` object
  that contains the time the data set was created in the `generated` and
  `generatedTime` fields as Unix and ISO time stamps, respectively.
  ([#605])
* The JSON output of the `validate` command and the of the `/validity`
  HTTP endpoint now include a `generatedTime` field that provides
  the generation time of the data set that was used for validation as an
  ISO time stamp. ([#605])
* The default RRDP timeout (via the `rrdp-timeout` option) has been increased
  to 300 seconds. ([#612])

New

* The maximum over delta steps performed during an update of an RRDP
  repository is now be limited via the `rrdp-max-delta` option. If more
  steps are necessary, the snapshot is used instead. This will improve the
  update times in cases where Routinator isn’t running constantly. The
  default limit is 100 steps. ([#615])
* It is now possible to disable the use of the gzip transfer encoding in
  the RRDP client via the new `rrdp-disable-gzip` option. ([#602])
* The start of a validation run is now logged as an info message.  ([#609])
* A reference to the global help appears now at the end of a sub-command’s
  help message. ([#607])
* A summary of the data set similar to the `summary` output format is now
  logged at log level info at the end of a validation run. ([#617])

Bug Fixes

* Catch and log error output from rsync. ([#577])
* Local exception files that contain prefix assertions with a shorter
  max-length than the prefix length are now rejected instead of adding
  these invalid prefix assertions to the output data set. ([#608])
* The `rrdp-timeout` command line option was setting both the RRDP timeout
  and the RRDP connection timeout. Now the `rrdp-connect-timeout` is
  correctly used for the latter. (Note: The config file was using the correct
  keys.) ([#611])
* Added `--rrdp-fallback-time` option to the command line parser. It was
  documented and supposed to be present previously, but wasn’t. ([#614])

Other

* In the JSON metrics for RRDP repositories, the fields `serial`,
  `session`, `delta`, and `snapshotReason` are left out entirely when the
  server reported not changes via a 304 response. ([#613])

[#577]: https://github.com/NLnetLabs/routinator/pull/577
[#590]: https://github.com/NLnetLabs/routinator/pull/590
[#601]: https://github.com/NLnetLabs/routinator/pull/601
[#602]: https://github.com/NLnetLabs/routinator/pull/602
[#604]: https://github.com/NLnetLabs/routinator/pull/604
[#605]: https://github.com/NLnetLabs/routinator/pull/605
[#607]: https://github.com/NLnetLabs/routinator/pull/607
[#608]: https://github.com/NLnetLabs/routinator/pull/608
[#609]: https://github.com/NLnetLabs/routinator/pull/609
[#611]: https://github.com/NLnetLabs/routinator/pull/611
[#612]: https://github.com/NLnetLabs/routinator/pull/612
[#613]: https://github.com/NLnetLabs/routinator/pull/613
[#614]: https://github.com/NLnetLabs/routinator/pull/614
[#615]: https://github.com/NLnetLabs/routinator/pull/615
[#617]: https://github.com/NLnetLabs/routinator/pull/617


## 0.9.0 ‘Raptor Bash for Life’

Released 2021-06-03.

No changes since 0.9.0-rc3.


## 0.9.0-rc3

Released 2021-05-31.

Breaking Changes

* The minimal supported Rust version is now 1.47.0. ([#568])

Bug Fixes

* Formatting fix for the man page ([#569])

Other Changes

* Support for building RPM packages for Centos 7 and 8. ([#566])

[#566]: https://github.com/NLnetLabs/routinator/pull/566
[#568]: https://github.com/NLnetLabs/routinator/pull/568
[#569]: https://github.com/NLnetLabs/routinator/pull/569


## 0.9.0-rc2

Released 2021-05-25.

Bug Fixes

* In server mode, the database is now only opened after detaching from the
  console if requested. This fixes Routinator hanging if the `--detach`
  option is used due to invoking multi-threading before forking. ([#557])
* Fixed a panic when trying to load a broken repository state object from
  the database. ([#558])
* Accept the `filter-asn` query parameter in the VRP set HTTP endpoints
  again which was accidentally rejected. ([#559])

Other Changes

* Rearranged the Prometheus metrics to be more canonical. ([#562])

[#557]: https://github.com/NLnetLabs/routinator/pull/557
[#558]: https://github.com/NLnetLabs/routinator/pull/558
[#559]: https://github.com/NLnetLabs/routinator/pull/559
[#562]: https://github.com/NLnetLabs/routinator/pull/562


## 0.9.0-rc1

Released 2021-05-17.

Breaking Changes

* Routinator now keeps the last valid data from a publication point and
  falls back to using that if an update to the publication point does not
  have a valid manifest or the data does not match the manifest. This data
  is stored in a [sled] key-value database rather than directly in the file
  system. ([#456])
* RRDP data is now collected into the same key-value database. The new
  command `dump` allows copying the data from the database to the file
  system. ([#473], [#480], [#484])
* If an RRDP repository is unavailable for a certain time, Routinator will
  now fall back to rsync. The time since last successful update before
  this fallback happens is randomly chosen for each repository
  between the refresh time and an upper limit configurable via the new
  `rrdp-fallback-time` option that defaults to one hour. ([#473], [#482],
  [#507])
* The `rsync-timeout` now describes a hard timeout on the rsync process
  for updating a repository. ([#528)]
* The size of downloaded RPKI objects is now limited by the
  `max-object-size` options which defaults to a limit of 20 MBytes. This
  limit applies to both RRDP and rsync. ([#531])
* Routinator now includes additional TALs for various commonly used
  RPKI testbeds. The `init` command has been restructured to make it
  possible to select the TALs for installation. The default is still to
  install the five production RIR TALs. ([#500])
* Deprecated configuration items have been removed: `unknown-objects`
  cannot be spelled with a underscore anymore and string values are not
  accepted anymore for `rtr-tcp-keepalive`. ([#496])
* The minimal supported Rust version is now 1.45.0. ([#444], [#498])

New

* The new option `--fresh` causes Routinator to delete all cached data
  before starting. This can be used when data corruption is reported. ([#470])
* The new HTTP server endpoint `/json-delta` provides an option to
  retrieve updates to a previously received data set via deltas. ([#537])
* A new output format `jsonext` is available both in the `vrps` command
  and the HTTP server that provides more detailed information about the
  sources of a VRP. ([#511])
* The `validate` command now accepts input from and can write its output
  to files. Both are available in simple plain text and JSON formatting.
  ([#514])
* The HTTP endpoints that supply the current VRP set now support
  conditional request handling. They include Etag and
  Last-Modified headers in their response and process If-None-Match and
  If-Modified-Since headers in requests. ([#474], contributed by [@reschke],
  [#488])
* The `vrps` command line option and the HTTP query parameters for
  limiting the VRPs included in the returned VRP set have been renamed
  from `filter-prefix` to `select-prefix` and from `filter-asn` to
  `select-asn` for clarity. The old options are still accepted. ([#511])
* Status information is now available in JSON format at `/api/v1/status`.
  ([#437])
* The metrics of RRDP repositories now also include the serial number of
  the last update. The JSON status information also includes the session
  ID and whether the last update was via a delta and if it wasn’t why a
  snapshot had to be used. It also separately provides the status codes
  for the request of the notification file and the snapshot or last
  requested delta file. ([#487], [#489])
* Prometheus metrics and JSON status have been greatly extended with more
  detailed counters for individual valid and invalid object types. They
  are also now available on a per-repository basis in addition to the
  already existing per-TAL basis. ([#493], [#539])
* Prometheus metrics and JSON status can now optionally include per-client
  RTR metrics. This is disabled by default to avoid accidentally leaking
  information about the local network topology. ([#519])
* The RRDP client now supports the gzip transfer encoding for HTTPs.
  ([#463], contributed by [@bjpbakker])
* The `exception` config file value now also accepts a single string with
  a path name instead of an array of strings. ([#471])
* The new `rrdp-keep-responses` option allows optionally storing the XML
  content of all received RRDP responses in the file system. ([#490])

Bug Fixes

* The `csvcompat` output format that was introduced in 0.7.0 is now
  actually accepted by the `--format` command line option.
* The `/validity` HTTP endpoint now accepts percent-encoded characters in
  the query parameters. ([#505])

Other Changes

* Updated the bundled APNIC and LACNIC TALs. When upgrading, please re-install
  the TALs in your system via `routinator init`. ([#510], [#543])
* Upgrade [rpki-rs] to 0.11 and drop now unnecessary separate dependency
  to [rpki-rtr]. ([#443])
* Upgrade Tokio-related dependencies to new version based on Tokio 1.0.
  ([#444])
* Upgrade the bundled UI to version 0.2.0 reflecting the changed metrics.
  ([#550])

[#437]: https://github.com/NLnetLabs/routinator/pull/437
[#443]: https://github.com/NLnetLabs/routinator/pull/443
[#444]: https://github.com/NLnetLabs/routinator/pull/444
[#456]: https://github.com/NLnetLabs/routinator/pull/456
[#463]: https://github.com/NLnetLabs/routinator/pull/463
[#471]: https://github.com/NLnetLabs/routinator/pull/471
[#470]: https://github.com/NLnetLabs/routinator/pull/470
[#473]: https://github.com/NLnetLabs/routinator/pull/473
[#474]: https://github.com/NLnetLabs/routinator/pull/474
[#480]: https://github.com/NLnetLabs/routinator/pull/480
[#482]: https://github.com/NLnetLabs/routinator/pull/482
[#484]: https://github.com/NLnetLabs/routinator/pull/484
[#487]: https://github.com/NLnetLabs/routinator/pull/487
[#488]: https://github.com/NLnetLabs/routinator/pull/488
[#489]: https://github.com/NLnetLabs/routinator/pull/489
[#490]: https://github.com/NLnetLabs/routinator/pull/490
[#493]: https://github.com/NLnetLabs/routinator/pull/490
[#496]: https://github.com/NLnetLabs/routinator/pull/496
[#498]: https://github.com/NLnetLabs/routinator/pull/498
[#500]: https://github.com/NLnetLabs/routinator/pull/500
[#505]: https://github.com/NLnetLabs/routinator/pull/505
[#507]: https://github.com/NLnetLabs/routinator/pull/507
[#510]: https://github.com/NLnetLabs/routinator/pull/510
[#511]: https://github.com/NLnetLabs/routinator/pull/511
[#514]: https://github.com/NLnetLabs/routinator/pull/514
[#519]: https://github.com/NLnetLabs/routinator/pull/519
[#528]: https://github.com/NLnetLabs/routinator/pull/528
[#531]: https://github.com/NLnetLabs/routinator/pull/531
[#537]: https://github.com/NLnetLabs/routinator/pull/537
[#539]: https://github.com/NLnetLabs/routinator/pull/539
[#543]: https://github.com/NLnetLabs/routinator/pull/543
[#550]: https://github.com/NLnetLabs/routinator/pull/550
[rpki-rs]: https://github.com/NLnetLabs/rpki-rs/
[rpki-rtr]: https://github.com/NLnetLabs/rpki-rtr/
[@bjpbakker]: https://github.com/bjpbakker
[@reschke]: https://github.com/reschke


## 0.8.3 ‘Like and Subscribe’

Released 2021-02-02.

There have been no changes since 0.8.3-rc1.


## 0.8.3-rc1

Released 2021-01-28.

New

* Status information is now available in JSON format at `/api/v1/status`
  ([#449]).
* Includes version 0.1.0 of [routinator-ui], a UI for Route Origin Validation
  and Routinator status ([#449]).

[#449]: https://github.com/NLnetLabs/routinator/pull/449
[routinator-ui]: https://github.com/NLnetLabs/routinator-ui/


## 0.8.2 ‘Once More, with Feeling’

Released 2020-12-09.

There have been no changes since 0.8.1-rc1.


## 0.8.2-rc1

Released 2020-12-04.

Changes

* As the rules proposed by [draft-ietf-sidrops-6486bis] turned out to be too
  strict, validation has been relaxed again. A CA is now only rejected and
  all its objects ignored if the manifest or CRL are invalid or if any of
  the objects listed on the manifest are either missing or have a
  different hash. ([#438])

Bug Fixes

* Switch logging to the configured target for the `update` command. ([#433])

Other Changes

* Update minor dependencies in `Cargo.lock`. ([#439]) 

[#433]: https://github.com/NLnetLabs/routinator/pull/433
[#438]: https://github.com/NLnetLabs/routinator/pull/438
[#439]: https://github.com/NLnetLabs/routinator/pull/439


## 0.8.1 ‘Pure as New York Snow’ 

Released 2020-11-30.

There have been no changes since 0.8.1-rc1.


## 0.8.1-rc1

Released 2020-11-20.

Bug Fixes

* VRPs filtered via local exceptions are dropped again. In 0.8.0, they
  were only added to the metrics but not actually dropped. ([#424],
  discovered by [@cwiech])
* The prefix validation option incorrectly matched VRPs for host prefixes
  to prefixes with an identical bit pattern of any length. (Found by
  [@vamseedhar-reddyvari] and fixed in [#415] by [@morrowc] and
  [@aaronw112358])
* The config file option for the policy on dealing with objects on unknown
  types is now correctly spelled `unknown-objects` (with a dash rather
  than an underscore). The old spelling will be also be accepted in 0.8
  releases. (Found and fixed by [@johannesmoos], [#413], [#416].)
* The config file option `rtr-tcp-keepalive` now accepts an integer value
  as it should have from the beginning (and the `config` command even
  created). For the time being, both integers and strings will be
  accepted. String values will be rejected starting with 0.9.0.
  ([#427], discovered by [@johannesmoos])

New

* The log output of the HTTP `/log` endpoint now states the start date of
  the validation run it represents. ([#426])

[#413]: https://github.com/NLnetLabs/routinator/pull/413
[#415]: https://github.com/NLnetLabs/routinator/pull/415
[#416]: https://github.com/NLnetLabs/routinator/pull/416
[#424]: https://github.com/NLnetLabs/routinator/pull/424
[#426]: https://github.com/NLnetLabs/routinator/pull/426
[@johannesmoos]: https://github.com/johannesmoos
[@morrowc]: https://github.com/morrowc
[@aaronw112358]: https://github.com/aaronw112358
[@cwiech]: https://github.com/cwiech


## 0.8.0 ‘Strikes and Gutters, Ups and Downs’

Released 2020-10-19.

There have been no changes since RC2.


## 0.8.0-rc2

Released 2020-10-09.

Bug Fixes

* Apply unsafe filter (if requested) also on subsequent validation runs in
  server mode. ([#407])
* Update all metrics on all validation runs. ([#407])
* Show the status code instead of -1 in RRDP status metrics. ([#408])

Other Changes

* Improve log message when listing resources being added to the unsafe
  filter list. ([#406])

[#406]: https://github.com/NLnetLabs/routinator/pull/406
[#407]: https://github.com/NLnetLabs/routinator/pull/407
[#408]: https://github.com/NLnetLabs/routinator/pull/408


## 0.8.0-rc1

Released 2020-10-07.

Breaking Changes

* Validation now follows the rules suggested by
  [draft-ietf-sidrops-6486bis]\: Any invalid object mentioned on the
  manifest will lead to the issuing CA and all its objects being rejected.
  However, unlike suggested by the draft, Routinator currently will not fall
  back to cached older versions of the CA’s objects that may still be valid.
  In addition, unknown RPKI object types are currently accepted with a
  warning logged. This behaviour can be changed via the `unknown-types`
  policy option. ([#371], [#401])
* Similarly, CRL handling has been tightened significantly. Each CA must
  now have exactly one CRL which must be the one stated in the manifest’s
  EE certificate. Any violation will lead to the whole CA being rejected
  with the same consequences as above. ([#397])
* The default for dealing with stale objects has been changed to `reject`
  in accordance with the same draft. ([#387])
* Parsing of local exception files is now more strict in accordance with
  [RFC 8416]. Any additional member in the JSON objects will lead to an
  error. However, error reporting has been greatly improved and now the
  line and column of an error will be indicated. ([#372])
* The alias `--allow-dubios-hosts` for the correctly spelled option has
  been removed. ([#384])
* The minimal supported Rust version is now 1.42.0.

New

* All VRPs overlapping with resources from rejected CAs – dubbed ‘unsafe
  VRPs’ can filtered via the new `unsafe-vrps` option. Doing so will avoid
  situations were routes become RPKI invalid if their VRPs are split over
  multiple CAs or there are less specific ROAs. By default, unsafe VRPs
  are only warned about. ([#377], [#400])
* New metrics for the VRPs produced and filtered on the various TALs.
  ([#377])
* The logging output of the latest validation run is now available via the
  HTTP service’s `/log` endpoint. ([#396])
* TCP keep-alive is now supported and enabled by default on RTR
  connections as suggested by [RFC 8210]. It can be disabled and its idle
  time changed from the default 60 seconds via the new `rtr-tcp-keepalive`
  command line and config file option. ([#390])
* The `pid-file`, `working-dir`, `chroot`, `user`, and `group` config file
  and server command options now also work without the `--detach` command
  line option. ([#392])
* The `init` command will now change ownership of the cache directory if
  the `user` and `group` options are set via config file or command line
  options. ([#392])
* Irrelevant log messages from libraries are now also filtered when using
  syslog logging. ([#385])
* Release builds will now abort on panic, i.e., when an unexpected
  internal condition is detected. This ensures that there won’t be a
  Routinator in a coma. ([#394])
* The feature `rta` enables the new command `rta` for validating Resource
  Tagged Assertions as described in [draft-michaelson-rpki-rta]. This
  feature is not enabled by default and needs to be activated by adding
  the option `--features rta` to the Cargo build command.

Bug Fixes

* Update start and end times will not change between consecutive metrics
  reports any more. ([#389])
* Local exceptions will now be loaded before starting a validation run
  both in vrps and server mode instead of discarding the run after it
  finished when loading fails. In server mode, we now wait 10 seconds
  after loading local exceptions fails and try again instead of repeatedly
  starting validation runs and discarding them. ([594186c])
* EE certificates encountered in the repository are now validated as
  router certificates rather than regular RPKI EE certificates. ([#398])

Other Changes

* Logging has been cleaned up. The meaning of the four log levels is now
  better defined – see the man page – and all log output has been
  reassigned accordingly. ([#396])


[#357]: https://github.com/NLnetLabs/routinator/pull/357
[#371]: https://github.com/NLnetLabs/routinator/pull/371
[#372]: https://github.com/NLnetLabs/routinator/pull/372
[#377]: https://github.com/NLnetLabs/routinator/pull/377
[#384]: https://github.com/NLnetLabs/routinator/pull/384
[#385]: https://github.com/NLnetLabs/routinator/pull/385
[#387]: https://github.com/NLnetLabs/routinator/pull/387
[#389]: https://github.com/NLnetLabs/routinator/pull/389
[#390]: https://github.com/NLnetLabs/routinator/pull/390
[#392]: https://github.com/NLnetLabs/routinator/pull/392
[#394]: https://github.com/NLnetLabs/routinator/pull/394
[#396]: https://github.com/NLnetLabs/routinator/pull/396
[#397]: https://github.com/NLnetLabs/routinator/pull/397
[#398]: https://github.com/NLnetLabs/routinator/pull/398
[#400]: https://github.com/NLnetLabs/routinator/pull/400
[#401]: https://github.com/NLnetLabs/routinator/pull/401
[594186c]: https://github.com/NLnetLabs/routinator/commit/594186cc2e1521a258f960c4196131e29f6cb1f9
[RFC 8210]: https://tools.ietf.org/html/rfc8210
[RFC 8416]: https://tools.ietf.org/html/rfc8416
[draft-ietf-sidrops-6486bis]: https://datatracker.ietf.org/doc/draft-ietf-sidrops-6486bis/
[draft-michaelson-rpki-rta]: https://datatracker.ietf.org/doc/html/draft-michaelson-rpki-rta


## 0.7.1 ‘Moonlight and Love Songs’

Released 2020-06-15.

There have been no changes since RC2.


## 0.7.1-rc2

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
