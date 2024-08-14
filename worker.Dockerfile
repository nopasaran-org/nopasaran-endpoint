# Use a base image, for example, Ubuntu
FROM ubuntu:latest

# Set environment variables if needed (e.g., for non-interactive installation)
ENV DEBIAN_FRONTEND=noninteractive

# Update and upgrade packages, and install any necessary dependencies
RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    openssh-client \
    openssh-server \
    python3-pip \
    python3-venv \
    git \
    rsync \
    libffi-dev \
    curl \
    build-essential \
    jq \
    libjpeg-dev \
    zlib1g-dev \
    libssl-dev \
    libffi-dev \
    libpq-dev \
    cargo

# Install Netbird
RUN curl -fsSL https://pkgs.netbird.io/install.sh | sh
RUN rm /etc/netbird/config.json

# Install Rust and Cargo
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Create a directory to copy your "resources" folder into
WORKDIR /app

# Copy the "resources" folder into the container
COPY resources /app/resources

# Create a virtual environment
RUN python3 -m venv venv

# Make sure we use the virtual environment's Python
ENV PATH="/app/venv/bin:$PATH"

# Update pip and install Python packages from requirements.txt
RUN python -m pip install --upgrade pip && \
    python -m pip install -r resources/requirements.txt

# Create worker and master users with random passwords of length 20
RUN useradd -m -s /bin/bash worker && \
    useradd -m -s /bin/bash master && \
    echo "worker:$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 20 ; echo '')" | chpasswd && \
    echo "master:$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 20 ; echo '')" | chpasswd

# Create a directory for SSH host keys
RUN mkdir /var/run/sshd

# Create a directory for X509 components
RUN mkdir /x509

# Set root password (change this for production use)
RUN echo 'root:your_password' | chpasswd

# Change SSH port to 1963 in sshd_config
RUN sed -i 's/#Port 22/Port 1963/' /etc/ssh/sshd_config

# Modify the SSHD configuration file for logging settings
RUN sed -i 's/#SyslogFacility AUTH/SyslogFacility AUTH/' /etc/ssh/sshd_config && \
    sed -i 's/#LogLevel INFO/LogLevel VERBOSE/' /etc/ssh/sshd_config

# Copy the scripts into the container
COPY entry.sh /app/entry.sh

# Make the scripts executable
RUN chmod +x /app/entry.sh

# Run the entry.sh script when the container starts
CMD ["/app/entry.sh"]
