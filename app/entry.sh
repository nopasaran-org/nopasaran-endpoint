#!/bin/bash 

netbird service start
pip install --upgrade pip
pip install --upgrade nopasaran

git config --global credential.helper store
echo "https://$GITHUB_TOKEN@github.com" > ~/.git-credentials

python /app/iptables/iptables_helper.py
python /app/tasks_consumer.py & disown

python /app/endpoint.py