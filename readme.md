run tests with:
```
cd vm_image
export RUST_BACKTRACE=1 && cargo build --release && pushd dockerimage && bash build-img.sh && popd && ../target/release/e2e_test --config vmconfig.json
```
