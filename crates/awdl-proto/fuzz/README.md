# awdl-proto fuzzing

Two cargo-fuzz targets:
- **`frame`**: for any MPDU that `parse` accepts, the raw re-emit, the
  typed re-emit of each TLV, and the rebuilt frame must all equal the input.
  Accessors must not panic.
- **`tlv`**: the same check for a single value. The first byte is the TLV
  type and the rest is its value.

cargo-fuzz needs nightly Rust and works best on Linux. On Windows, run it in
a container:

```powershell
cargo run -p awdl-proto --example fuzz_seeds   # seeds from the fixture and local captures
wslc run --rm -v "D:\repositories\Warlock:/src" -w /src/crates/awdl-proto/fuzz `
  -e CARGO_TARGET_DIR=/tmp/target rust:latest bash -c `
  "rustup toolchain install nightly --profile minimal && cargo install cargo-fuzz --locked && cargo +nightly fuzz run frame -- -max_total_time=600"
```

`corpus/` and `artifacts/` are gitignored. Seeds made from the private
captures contain real devices' addresses and names, so they stay local.
