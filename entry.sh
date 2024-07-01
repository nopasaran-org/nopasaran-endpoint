#!/bin/bash

netbird service start

python /app/resources/controller_link.py & disown

rsyslogd

if [ "$ROLE" = "manager" ]; then
    python /app/resources/ssh_accepted_connections.py & disown
fi

./update_nopasaran.sh & disown

/usr/sbin/sshd -D
