set -e
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
