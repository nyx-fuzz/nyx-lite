Experimenting with firecracker for snapshot fuzzing
======


Setup:
-----

1) Install Docker (you may or may not want to follow the installation steps in `dockerfile/install-docker.sh`, whatever
way works for you)
2) Run `dockerfile/build-img.sh`, this will extract a rootfs from the fockerfile. It will call initscript-fuzz-setup.sh
as part of it's init.
3) Run `download_kernel.sh` to download vmlinux-6.1.58 (really, any other firecracker compatible  kernel will work as well - you can also use
the official guidelines to compile your own, if you feel like it).
4) Run `setup_networking.sh` to setup a bridged network with the VM
5) Run `run.sh` to actually start the VM
6) Log into the VM via the tty, or by running `ssh-root.sh`
