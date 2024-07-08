#!/bin/bash

while true; do
    netbird service start
    pip install --upgrade pip
    pip install --upgrade nopasaran
    sleep 300
done
