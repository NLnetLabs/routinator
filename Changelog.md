# Change Log

## Next Version

Breaking Changes

* Add trust anchor information to the CSV, JSON, and RPSL output. [(#21)]

New

* Add a `Dockerfile` for building and deploying through Docker. Thanks to
  David Monosov. [(#23)]
* Output from the rsync runs is now send to the logger and will be handled
  according to log settings. Output to stderr is logged with log level
  _warn,_ stdout is logged with _info._ [(#27)]
* In daemon mode, forking now happens _after_ the TALs are checked so that
  you can see the error messages and that it fails.
* New VRP output format `openbgpd` which produces a `roa-set` for
  [OpenBGPD](http://www.openbgpd.org/) config.
  Thanks to Job Snijders. [(#32)]

Bug Fixes

* The default output format was accidentally changed to `none`. It is
  `csv` again.

Performance Improvements

* Caching of CRL serial numbers for CAs with large manifests leads to
  about half the validation time for the current repository. [(XX)]


Dependencies

[(#21)]: https://github.com/NLnetLabs/routinator/pull/21
[(#23)]: https://github.com/NLnetLabs/routinator/pull/23
[(#27)]: https://github.com/NLnetLabs/routinator/pull/27
[(#32)]: https://github.com/NLnetLabs/routinator/pull/32


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

