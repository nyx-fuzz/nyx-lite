FROM alpine:latest
RUN apk update \
 && apk add openrc openssh sudo util-linux bash vim rsyslog

COPY interfaces.txt /etc/network/interfaces
COPY initscript-fuzz-setup.sh /etc/init.d/fuzz-setup
RUN  chmod +x /etc/init.d/fuzz-setup
COPY ./key.pub /root/.ssh/authorized_keys

RUN echo "basic services" \
 && ln -s agetty /etc/init.d/agetty.ttyS0 \
 && echo ttyS0 > /etc/securetty \
 && rc-update add agetty.ttyS0 default \
 && rc-update add devfs boot \
 && rc-update add procfs boot \
 && rc-update add sysfs boot \
 && rc-update add fuzz-setup default \
 && echo "done"
