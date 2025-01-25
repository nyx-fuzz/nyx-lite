#!/sbin/openrc-run

start() {
  ifup -i /etc/network/interfaces eth0
  ifup -i /etc/network/interfaces lo
  #setup root login
  chmod 0740 /root/
  chmod 0700 /root/.ssh
  chmod 0400 /root/.ssh/authorized_keys
  # password for user root is "fuzz"
  echo "root:fuzz" | chpasswd

  #setup fuzz user
  addgroup -S fuzz
  adduser -S fuzz -G fuzz -h /home/fuzz -s /bin/bash
  mkdir -p /home/fuzz/.ssh
  cp /root/.ssh/authorized_keys ./home/fuzz/.ssh
  chown -R fuzz:fuzz /home/fuzz
  chmod 0740 /home/fuzz
  chmod 0700 /home/fuzz/.ssh
  chmod 0400 /home/fuzz/.ssh/authorized_keys
  # password for user fuzz is "fuzz"
  echo "fuzz:fuzz" | chpasswd
  echo '%fuzz ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/fuzz
  #setup pts for ssh to work properly 
  mkdir /dev/pts
  mount devpts /dev/pts -t devpts
  #start sshd
  #rc-service sshd start
  /resources/test_swbp
  echo "ABOUT TO SHUT DOWN VIA SHELL!"
  reboot -f 
  echo "STILL RUNNING???"
	return 0
}
