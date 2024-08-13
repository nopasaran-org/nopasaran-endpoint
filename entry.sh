#!/bin/bash 

netbird service start
pip install --upgrade pip
pip install --upgrade nopasaran

python /app/resources/controller_link.py & disown

/usr/sbin/sshd -D
