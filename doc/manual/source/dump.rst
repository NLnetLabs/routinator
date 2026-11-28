Dumping Stored Data
===================

The :subcmd:`dump` subcommand writes the contents of all stored data to the file
system. This is primarily intended for debugging but can be used to get access
to the view of the :term:`RPKI <Resource Public Key Infrastructure (RPKI)>` data that
Routinator currently sees. This subcommand has
only one option, :option:`--output`, which specifies the directory where the
output should be written.

Three directories will be created in the output directory:

rrdp
    This directory contains all the files collected via :term:`RRDP <RPKI Repository Delta
    Protocol (RRDP)>` from the various
    :term:`repositories <Repository>`. Each repository is stored in its own
    directory. The mapping
    between ``rpkiNotify`` URI and path is provided in the
    :file:`repositories.json` file. For each repository, the files are stored in
    a directory structure based on the components of the file as :term:`rsync URI`.

rsync
    This directory contains all the files collected via rsync. The files are
    stored in a directory structure based on the components of the file's rsync
    URI.

store
    This directory contains all the files used for validation. Files collected
    via RRDP or rsync are copied to the
    store if they are correctly referenced
    by a valid :term:`manifest`. This part contains one directory for each RRDP
    repository similarly structured to the :file:`rrdp` directory and one
    additional directory :file:`rsync` that contains files collected via rsync.

ta
    This directory contains the :term:`trust anchor <Trust Anchor (TA)>` certificates.
    Files are stored
    in a directory structure two levels deep. The first level is the schema
    portion of the certificate’s URI, i.e., ``https`` or ``rsync``, and the
    second level is the authority portion of the URI, e.g., ``tal.apnic.net``.
    Within this second level, the certificate is stored in a file that has
    the hexadecimal encoding of the SHA-256 hash of the certificate’s URI
    as the file name with the extension ``.cer`` appended.
