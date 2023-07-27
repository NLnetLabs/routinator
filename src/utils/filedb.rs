//! A very simple in-file database.
//!
//! This module contains a file system-in-a-file that is tailored towards
//! the needs of Routinator. It can be used to store objects containing
//! binary data. These objects can only be created, replaced, or deleted
//! but not modified. The whole file system can grow and shrink as needed.
//!
//!
//! # Architecture
//!
//! The system is based on a smallest unit of data called a block with a
//! pre-defined size that is a power of two. A pre-defined number of block,
//! also a power of two, forms a super-block. The system can grow and shrink
//! by super-blocks only.
//!
//!
//! ## Accounting blocks
//!
//! The first block of each super block is an accounting block. It stores
//! information about available blocks in the super block.
//!
//! It starts with a super block type identifying the accounting block as a
//! simple accounting block or a complex accounting block. This is then
//! followed by the simple or complex accounting block.
//!
//! ### Simple accounting block
//!
//! This is used for super blocks where each block is one file. This makes
//! sense because most files in RPKI are tiny. The accounting information is
//! a simple bit field indicatin which blocks in the super block are
//! occupied. This includes the accounting block itself for simplicity.
//!
//! ### Complex accounting block
//!
//! This is used for super blocks that allow files to occupy more than one
//! block. These files are kept in a single consecutive sequence of blocks if
//! at all possible. The accounting block contains a list of block sequences
//! that are currently available. Each item consists of a block identifier
//! and an octets length of an empty sequence of blocks. The list ends with
//! an entry of both the block identifier and the length of zero.
//!
//! ### Root accounting block
//!
//! The very first block of the very first super block is a simple accounting
//! block but it starts off with a magic cookie identifying the file type and
//! endianness, as well as protocol version, block size, and super block size.
//!
//! ## Directory blocks
//!
//! Directory information, i.e., a mapping between file names and their data,
//! is stored in blocks. Such a block starts with a directory type which
//! identifies the block as either a naive or an index directory. The type
//! is followed by that.
//!
//! The root directory is located in the second block of the first super
//! block.
//!   
//! ### Naive directory
//!
//! A file with a list of entries. Each entry consists of a length-preceeded
//! string with the file name, followed by a mode octet, followed by a
//! length-preceeded list of block sequences, each consisting of a block
//! identifier and a length of data.
//!
//! The mode octet currently only identifies an entry as a file or directory.
//! We do not support permissions.
//!
//! ### Index directory
//!
//! A file with a list of entries. Each entry consists of the first and last
//! hash of file name and a block indentifier for the naive directory holding
//! these hashes. The last hash of an entry and the first hash of the next
//! entry may be identical.
//!
//! # Block identifiers:
//!
//! These are actual file positions in a `u64`. The last bits corresponding
//! to the block size are unused and must be zero. The start of the super
//! block can be determined by zeroing out the next bits corresponding to the
//! number of blocks in the super block.

