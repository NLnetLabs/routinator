# Change Log

## Unreleased Next Version

Breaking Changes

New

* New output format `csvext` that mimics the output format of the Original
  RIPE NCC Validator. [(#59)]

* Support for alternative resource extensions and validation defined in
  [RFC 8360]. [(#63)]


Bug Fixes

* Converts the endianess of the serial number in the SerialNotify RTR PDU.
  Reported by Massimiliano Stucchi. [(#60)]

Dependencies


[(#59)]: https://github.com/NLnetLabs/routinator/pull/59
[(#60)]: https://github.com/NLnetLabs/routinator/pull/60
[(#63)]: https://github.com/NLnetLabs/routinator/pull/63



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

