# NOCTYRA parser fuzzing

This is a standalone cargo-fuzz workspace and is intentionally excluded from the main Cargo workspace.

Install cargo-fuzz, then run from this directory:

```sh
cargo fuzz run nmf2_manifest
```

The target exercises the NMF2 manifest parser only. It does not perform password KDF or decrypt archives, keeping fuzz iterations fast. It must be supplemented with authenticated archive integration tests and image decoder fuzz targets before release.

Do not treat a clean fuzz run as proof of parser safety.
