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

On a Debian (and presumbaly Ubuntu) system, it goes somewhat like this:

```bash
sudo apt-get install musl-tools
rustup target add x86_64-unknown-linux-musl
cargo build --target=x86_64-unknown-linux-musl --release
```

