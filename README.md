# l4lb

L4LB is an eBPF layer 4 load balancer written in Rust using the [Aya
library](https://github.com/aya-rs/aya). L4LB uses
[XDP](https://docs.cilium.io/en/latest/bpf/) to mangle and route packets
directly in the kernel, theoretically providing very fast packet processing.

It is influenced heavily by
[Katran](https://github.com/facebookincubator/katran), Meta's high performance
C++ load balancer.

## Prerequisites

1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag.

## Build Userspace

```bash
cargo build
```

## Run

```bash
RUST_LOG=info cargo xtask run -- --config <config file>
```
