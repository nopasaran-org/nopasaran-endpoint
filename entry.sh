#!/bin/bash 

source /app/resources/config.env

netbird service start
pip install --upgrade pip
pip install --upgrade nopasaran

python /app/resources/iptables_rules.py

python /app/resources/coordinator_link.py & disown

/usr/sbin/sshd -D
