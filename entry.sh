#!/bin/bash

netbird service start

python /app/resources/controller_link.py & disown

./update_nopasaran.sh & disown

/usr/sbin/sshd -D
