#!/bin/bash

python /app/resources/controller_link.py & disown

/usr/sbin/sshd -D