#!/bin/bash

./update_nopasaran.sh & disown

python /app/resources/controller_link.py & disown

/usr/sbin/sshd -D
