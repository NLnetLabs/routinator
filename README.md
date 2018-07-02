# A RPKI Relying Party in Rust

## Getting Started (aka What’s that Rust thing you keep going on about?)

If you don’t have it yet, you need Rust. There’s a tool called *rustup*
for that. If you feel lucky, simply do:

```bash
curl https://sh.rustup.rs -sSf | sh
```

or get the file, have a look and then run it manually.

Make sure `cargo` is in your path (*rustup* should tell you what to do),
then, in the directory you cloned this repository to, say

```bash
cargo build
```

This will build the whole thing (or fail, of course). If it succeeds, you
can run

```bash
cargo run
```

to run the binary that has been built. At this point, it will rsync all
repository instances into `./test/repository` and validate them. You will
need the `rsync` executable in your path.

