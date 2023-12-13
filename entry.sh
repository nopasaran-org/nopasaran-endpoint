#!/bin/bash

python /app/resources/controller_link.py & disown

rsyslogd

if [ "$ROLE" = "manager" ]; then
    python /app/resources/ssh_accepted_connections.py & disown
fi

/usr/sbin/sshd -D
