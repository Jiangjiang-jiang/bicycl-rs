# bicycl-rs

Rust bindings for [upstream BICYCL](https://gite.lirmm.fr/crypto/bicycl).

- `bicycl-rs-sys`: low-level FFI bindings to the BICYCL C API
- `bicycl-rs`: safe Rust wrapper built on top of `bicycl-rs-sys`

## Build

Default development flow uses vendored C API sources:

```bash
cargo test --workspace
```

To use prebuilt system libraries instead of vendored sources:

```bash
bash scripts/test-system-from-vendored.sh
```

If libraries are not in the default linker search path (e.g. macOS with Homebrew):

```bash
BICYCL_CAPI_LIB_DIR=/path/to/prebuilt/lib \
BICYCL_DEP_LIB_DIR=$(brew --prefix gmp)/lib:$(brew --prefix openssl@3)/lib \
cargo test -p bicycl-rs --no-default-features --features system
```

Upstream BICYCL sources are tracked as a git submodule in `bicycl-rs-sys/vendor/bicycl/`. To update: `git submodule update --remote bicycl-rs-sys/vendor/bicycl`.

## Platform Support

Linux, macOS, and Windows (MinGW).

## License

`GPL-3.0-or-later`.
