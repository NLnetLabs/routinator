# Change Log

## Unreleased next version

Breaking

New

Bug Fixes

* Print errors when reading the trust anchor locators to standard error
  instead of logging them since logging isn’t set up yet at that point.
  [(#89)]

Dependencies

[(#89)]: https://github.com/NLnetLabs/routinator/pull/89


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
