#!/bin/bash

python /app/resources/controller_link.py & disown

rsyslogd

# Construct the API endpoint URL using environment variables
url="http://$SERVER_HOST:$SERVER_PORT/api/v1/netbird_setup_key/$ENDPOINT_NAME/$AUTHORIZATION_TOKEN"

# Use curl to fetch the setup key
key_setup=$(curl -s "$url" | jq -r '.mesh_key_setup')

# Replace placeholders in the command and execute netbird setup
# Include dots between the fields in the hostname
netbird_command="netbird up --setup-key $key_setup --hostname ${ENDPOINT_NAME}.${ROLE}.${SERVER_DOMAIN_NAME}"
eval "$netbird_command"

if [ "$ROLE" = "manager" ]; then
    python /app/resources/ssh_accepted_connections.py & disown
fi

/usr/sbin/sshd -D
