#!/bin/bash 

netbird service start
pip install --upgrade pip
pip install --upgrade nopasaran

python /app/iptables/iptables_helper.py

python /app/tasks_consumer.py & disown

python /app/endpoint.py
