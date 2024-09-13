# Use a base image with Ansible pre-installed (e.g., Ubuntu)
FROM ubuntu:latest

# Set environment variables if needed (e.g., for non-interactive installation)
ENV DEBIAN_FRONTEND=noninteractive

# Update and upgrade packages, and install any necessary dependencies
RUN apt-get update && apt-get upgrade -y && apt-get install -y \ 
    iptables \
    python3-pip \
    python3-venv \
    python3-dev \
    curl \
    git \
    build-essential \
    jq \
    libjpeg-dev \
    zlib1g-dev \
    libssl-dev \
    libffi-dev \
    libpq-dev \
    cargo \
    rustc \
    libpcap-dev \
    tcpdump

# Install Netbird
RUN curl -fsSL https://pkgs.netbird.io/install.sh | sh
RUN rm /etc/netbird/config.json

# Create a directory to copy the app folder into
WORKDIR /app

# Copy the app folder into the container
COPY ./app /app

# Create a virtual environment
RUN python3 -m venv venv

# Make sure we use the virtual environment's Python
ENV PATH="/app/venv/bin:$PATH"

# Update pip and install Python packages from requirements.txt
RUN python -m pip install --upgrade pip && \
    python -m pip install -r /app/requirements.txt

# Create a directory for X509 components
RUN mkdir /x509

# By default, sleep to keep the container running for manual interaction
CMD ["/app/entry.sh"]