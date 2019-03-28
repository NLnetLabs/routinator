# Miscellaneous Documentation Items

This file contains a random collections of items worth remembering. It
will become part of the Owner’s Manual once that starts existing.

## Building a Statically Linked Routinator

While Rust binaries are mostly statically linked, they depend on libc
which, as least as glibc that is standard on Linux systems, is somewhat
difficult to link statically. This is why Routinator binaries are actually
dynamically linked on glibc systems and can only be transferred between
systems with the same glibc versions.

However, Rust can build binaries based on the alternative implementation
named musl that can easily be statically linked. Building such binaries is
easy with rustup. You need to install musl and the correct musl target
such as `x86_64-unknown-linux-musl` for x86\_64 Linux systems. Then you
can just build Routinator for that target.

On a Debian (and presumably Ubuntu) system, it goes somewhat like this:

```bash
sudo apt-get install musl-tools
rustup target add x86_64-unknown-linux-musl
cargo build --target=x86_64-unknown-linux-musl --release
```

## Building on CentOS 6

If you are trying to build Routinator on CentOS 6, you will end up with a
long list of error messages about missing assembler instructions. This is
because the assembler shipped with CentOS 6 is too old.

You can get the necessary version by installing the [Developer Toolset 6]
from the [Software Collections] repository. On a virgin system, you can
get Routinator in these six steps:

```
sudo yum install centos-release-scl
sudo yum install devtoolset-6
scl enable devtoolset-6 bash
curl https://sh.rustup.rs -sSf | sh
source $HOME/.cargo/env
cargo install routinator
```

[Developer Toolset 6]: https://www.softwarecollections.org/en/scls/rhscl/devtoolset-6/
[Software Collections]: https://wiki.centos.org/AdditionalResources/Repositories/SCL
