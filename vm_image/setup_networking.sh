set -eu

TAP_DEV="fc-88-tap0"

# set up the kernel boot args
MASK_LONG="255.255.255.252"
MASK_SHORT="/30"
TAP_IP="169.254.0.22"
GUEST_IP="169.254.0.21"
GUEST_MAC="02:FC:00:00:00:05"

# set up a tap network interface for the Firecracker VM to user
ip link del "$TAP_DEV" 2> /dev/null || true
ip tuntap add dev "$TAP_DEV" mode tap
sysctl -w net.ipv4.conf.${TAP_DEV}.proxy_arp=1 > /dev/null
sysctl -w net.ipv6.conf.${TAP_DEV}.disable_ipv6=1 > /dev/null
ip addr add "${TAP_IP}${MASK_SHORT}" dev "$TAP_DEV"
ip link set dev "$TAP_DEV" up

