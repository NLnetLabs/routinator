Logging
=======

To let you analyse the :term:`validated ROA payload (VRP)` data set as well as its
overall health, Routinator provides an extensive amount of information. The
information regarding its own health is written to the configured log.

All information about issues encountered during fetching and validating data
is stored separately and can be retrieved through the status HTTP endpoints.
It is collected per :term:`RRDP <RPKI Repository Delta Protocol (RRDP)>` or rsync
:term:`repository` and :term:`publication point`, rather
than as lines mixed in with the log, making it easier to see possible issues
for :term:`repositories <Repository>` or :term:`publication points <Publication Point>`.

You can also log the :term:`repository` log messages to syslog or a file. See the
manual for how to set this up.

Log levels are utilised to allow filtering this information for
particular use cases.

The log levels represent the following information:

error
      Information related to events that prevent Routinator from continuing to
      operate at all, as well as all issues related to local configuration even
      if Routinator will continue to run.

warn
      Information about events and data that influences the set of :term:`VRPs <Validated
      ROA Payload (VRP)>` produced
      by Routinator. This includes failures to communicate with :term:`repository`
      servers, or encountering invalid objects.

info
      Information about events and data that could be considered abnormal but do
      not influence the set of :term:`VRPs <Validated ROA Payload (VRP)>`  produced. For
      example, the ``warn`` policy logs individual
      :ref:`unsafe VRPs <data-processing:unsafe vrps>` at this level.

debug
      Information about the internal state of Routinator that may be useful for
      debugging.

Interactive Mode
----------------

When running :doc:`interactively<interactive>` logging information will be
printed to standard error by default. You can redirect logging to syslog using
the :option:`--syslog` option, or to a file with the :option:`--logfile` option.
You can influence the amount of information returned with these options:

``-v, --verbose``
      Print more information. If given twice, even more information is printed.
      More specifically, a single :option:`-v` increases the log level from the
      default of warn to *info*, specifying it twice increases it to *debug*.

``-q, --quiet``
      Print less information. Given twice, print nothing at all. A single
      :option:`-q` will drop the log level to *error*. Specifying :option:`-q`
      twice turns logging off completely.

Detached Server Mode
--------------------

When running Routinator detached in :doc:`server mode <daemon>`
logging to syslog is implied. Using the :option:`--syslog-facility` option you
can specify the syslog facility to use, which is *daemon* by default. You also
redirect logging output to a file using the :option:`--logfile` option.

.. Tip:: Though almost all settings are available as command line options, you
         would likely want to configure logging options in the
         :doc:`configuration file<configuration>`.

When you run the HTTP service logging information is also available at the
``/log`` path. This will produce logging output of the last validation
run. The log level matches that set upon start. Note that the output is
collected after each validation run and is therefore only available after the
initial run has concluded.

