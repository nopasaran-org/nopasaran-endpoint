# Endpoint (Master or Worker)

This repository contains the implementation of an **endpoint** that acts as either a **worker** or a **master** in a distributed testing system. It uses **WebSocket communication** to maintain bidirectional communication with a coordinator, and **Netbird** to set up a secure, mesh VPN for seamless communication between endpoints, even across firewalls.

## Overview

The system is designed to handle distributed test execution:

- **Master**: Responsible for receiving decision trees (test-trees) from the coordinator, where each node represents a test case.
- **Workers**: Execute the individual test cases assigned by the master. Each worker runs an embedded server to listen for the tests sent by the master.

Endpoints (both masters and workers) are **mutually authenticated** using **x509 certificates** provided by the coordinator, which acts as a certification authority.

**Netbird** is used to create a mesh VPN overlay network, ensuring that endpoints can communicate with each other securely, even if they are behind different firewalls. Visit [Netbird's website](https://www.netbird.io/) for more information.

## Prerequisites

- Install **Docker** and **Docker Compose** from their official websites:
  - [Docker](https://docs.docker.com/get-docker/)
  - [Docker Compose](https://docs.docker.com/compose/install/)

## Running the Endpoint

### Docker Compose Configuration

To set up an endpoint, create a `docker-compose.yml` file. This file should contain your specific configuration, which will be accessible via the coordinator dashboard.

Here’s an example of what the `docker-compose.yml` might look like:

```yaml
version: "3"
services:
  ENDPOINT_NAME_VALUE:
    container_name: ENDPOINT_NAME_VALUE
    image: benilies/nopasaran-worker # Use `benilies/nopasaran-master` if this is a master
    environment:
      - ENDPOINT_NAME=ENDPOINT_NAME_VALUE # Replace with your endpoint's name
      - AUTHORIZATION_TOKEN=SECRET # Replace with your authorization token
      - ROLE=worker or master # Set to "worker" or "master" depending on the role
    restart: always
    network_mode: "host"
    cap_add:
      - NET_ADMIN
      - SYS_PTRACE
  watchtower:
    image: containrrr/watchtower
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    restart: always
    command: ENDPOINT_NAME_VALUE --interval 60 --cleanup
```

### Configuration Options

- `ENDPOINT_NAME`: Unique identifier for your endpoint.
- `AUTHORIZATION_TOKEN`: The authorization token provided by the coordinator.
- `ROLE`: Set this to `master` if this is a master node, or `worker` if this is a worker node.
- `SERVER_HOST`: (Optional) Host address of a custom coordinator (e.g., `127.0.0.1` for localhost).
- `SERVER_PORT`: (Optional) Port used by the custom coordinator (default is `8000`).

### Example for a Custom Self-Hosted Coordinator

To connect to a custom, self-hosted coordinator, add the following environment variables:

```yaml
environment:
  - SERVER_HOST=127.0.0.1 # Replace with your coordinator's IP
  - SERVER_PORT=8000 # Replace with your coordinator's port
```

### Running the Endpoint

To run the endpoint, simply execute:

```bash
docker-compose up
```

This will start the endpoint with the configuration provided in the `docker-compose.yml` file.
