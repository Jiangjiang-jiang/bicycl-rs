# bicycl-rs

Rust bindings for upstream BICYCL.

This repository contains:

- `bicycl-rs-sys`: low-level FFI bindings to the BICYCL C API
- `bicycl-rs`: safe Rust wrapper built on top of `bicycl-rs-sys`

## Repository Layout

```text
.
├── bicycl-rs-sys/
├── bicycl-rs/
├── scripts/
└── .github/workflows/
```

## Build And Test

Default development flow uses vendored C API sources:

```bash
cargo test --workspace
```

To test `system` mode against prebuilt local libraries:

```bash
bash scripts/test-system-mode.sh
```

If `bicycl_capi` or its dependencies are not in the default linker search path, set
`BICYCL_CAPI_LIB_DIR` and `BICYCL_DEP_LIB_DIR`. Library names and link kinds can also
be overridden with `BICYCL_*_LIB_NAME` and `BICYCL_*_LINK_KIND`.

Vendored upstream sources live in `bicycl-rs-sys/vendor/bicycl/`. To resync them from upstream, run `bash scripts/update-vendor.sh [repo] [ref]`. The currently tracked upstream revision is recorded in `bicycl-rs-sys/vendor/bicycl-upstream.toml`.

## License

`GPL-3.0-or-later`.
