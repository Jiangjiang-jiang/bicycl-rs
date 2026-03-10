# bicycl-rs

Rust bindings for [upstream BICYCL](https://gite.lirmm.fr/crypto/bicycl).

- `bicycl-rs-sys`: low-level FFI bindings to the BICYCL C API
- `bicycl-rs`: safe Rust wrapper built on top of `bicycl-rs-sys`

## Build

```bash
cargo test --workspace
```

Upstream BICYCL sources are tracked as a git submodule in `bicycl-rs-sys/vendor/bicycl/`. To update: `git submodule update --remote bicycl-rs-sys/vendor/bicycl`.

## Platform Support

Linux, macOS, and Windows (MinGW).

## License

`GPL-3.0-or-later`.
