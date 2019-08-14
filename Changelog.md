# Change Log

## Unreleased future version

Breaking Changes

* Removed the `rsync-count` command line and configuration file option.
  This option is now unused as modules are now rsync only when they are
  first used. [(#187)]
* The default value for `refresh` has been lowered to 600 seconds.
  [(#191)]

News

* Routinator now supports RRDP for synchronizing repository content.
  [(#187)]
* Restructured repository directory. The rsync data now lives in a
  sub-directory called `rsync`. The main repository directory will now be
  kept clean and all unexpected files removed. [(#187)]
* In server mode, the repository will be refreshed and re-validated when
  the first object expires. [(#191)] 

Bug Fixes

[(#187)]: https://github.com/NLnetLabs/routinator/pull/187
[(#191)]: https://github.com/NLnetLabs/routinator/pull/191


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
