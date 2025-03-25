set -e


#rustc --target=x86_64-unknown-linux-musl ../../examples/test_guest_runner.rs -o 
pushd ../../test-binaries
cargo build --bin guest_test --target=x86_64-unknown-linux-musl --release
popd 
rm resources/guest_test
cp -L ../../test-binaries/target/x86_64-unknown-linux-musl/release/guest_test resources/guest_test

IMG_ID=$(docker build -q .)
CONTAINER_ID=$(docker run -td $IMG_ID /bin/bash)


MOUNTDIR=mnt
FS=rootfs.ext4
sudo rm -r -f $MOUNTDIR
sudo rm -f $FS

mkdir $MOUNTDIR
qemu-img create -f raw $FS 800M
mkfs.ext4 $FS
sudo mount $FS $MOUNTDIR
sudo docker cp $CONTAINER_ID:/ $MOUNTDIR
sudo umount $MOUNTDIR
rm -r $MOUNTDIR
docker stop $CONTAINER_ID
docker rm $CONTAINER_ID
