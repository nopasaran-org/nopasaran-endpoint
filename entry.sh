#!/bin/bash

python /app/resources/controller_link.py & disown

netbird service start
pip install --upgrade pip
pip install --upgrade nopasaran

/usr/sbin/sshd -D
