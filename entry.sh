#!/bin/bash 

netbird service start
pip install --upgrade pip
pip install --upgrade nopasaran

python /app/resources/iptables_rules.py

python /app/resources/coordinator_link.py & disown
python /app/resources/task_consumer.py & disown

/usr/sbin/sshd -D
