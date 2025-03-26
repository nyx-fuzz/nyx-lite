
Clone nyx-lite with:
```
git clone --recurse-submodules 'git@github.com:nyx-fuzz/nyx-lite.git'
git clone --recurse-submodules 'https://github.com/nyx-fuzz/nyx-lite.git'
```

Get a firecracker compatible linux kernel:
```
cd vm_image
bash download_kernel.sh
```

and run tests with:
```
cd vm_image
export RUST_BACKTRACE=1 && cargo build --release && pushd dockerimage && bash build-img.sh && popd && ../target/release/e2e_test --config vmconfig.json
```

