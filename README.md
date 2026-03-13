# bicycl-rs

Rust bindings for [upstream BICYCL](https://github.com/Jiangjiang-jiang/bicycl).

This workspace contains two crates:

- `bicycl-rs-sys`: low-level FFI bindings to the BICYCL C API
- `bicycl-rs`: safe Rust wrapper built on top of bicycl-rs-sys

## Building

```bash
cargo test --workspace
```

Requires CMake >= 3.16, GMP development headers, and OpenSSL development
headers. The upstream BICYCL C++ sources are vendored in
`bicycl-rs-sys/vendor/bicycl/` as a git submodule.

To update the vendored BICYCL sources:

```bash
git submodule update --remote bicycl-rs-sys/vendor/bicycl
```

## Platform Support

Linux, macOS, and Windows (MinGW).

## License

`GPL-3.0-or-later`.
