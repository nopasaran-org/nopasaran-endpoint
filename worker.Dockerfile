# Use a base image, for example, Ubuntu
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

# Create worker and master users with random passwords of length 20
RUN useradd -m -s /bin/bash worker && \
    useradd -m -s /bin/bash master && \
    echo "worker:$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 20 ; echo '')" | chpasswd && \
    echo "master:$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 20 ; echo '')" | chpasswd

# Add the master to the sudo group
RUN usermod -aG sudo master

# Configure sudoers to not require a password for the master
RUN echo "master ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Create a directory for SSH host keys
RUN mkdir /var/run/sshd

# Create a directory for X509 components
RUN mkdir /x509

# Run the entry.sh script when the container starts
CMD ["/app/entry.sh"]
