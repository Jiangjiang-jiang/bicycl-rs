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

Vendored upstream sources live in `bicycl-rs-sys/vendor/bicycl/`. To resync them from upstream, run `bash scripts/sync-vendor.sh [repo] [ref]`.

## Platform Support

Linux and macOS. Windows is not supported due to a type mismatch in upstream BICYCL
(`size_t` vs `mp_bitcnt_t` in `gmp_extras.inl`) on MinGW/LLP64 targets.

## License

`GPL-3.0-or-later`.
