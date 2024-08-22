# Use a base image with Ansible pre-installed (e.g., Ubuntu)
FROM ubuntu:latest

# Set environment variables if needed (e.g., for non-interactive installation)
ENV DEBIAN_FRONTEND=noninteractive

# Update and upgrade packages, and install any necessary dependencies
RUN apt-get update && apt-get upgrade -y && apt-get install -y \ 
    sudo \
    openssh-client \
    openssh-server \
    iptables \
    python3-pip \
    python3-venv \
    python3-dev \
    curl \
    git \
    rsync \
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
    tcpdump \
    ansible

# Install Netbird
RUN curl -fsSL https://pkgs.netbird.io/install.sh | sh
RUN rm /etc/netbird/config.json

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

# Add the master to the sudo group
RUN usermod -aG sudo master

# Configure sudoers to not require a password for the master
RUN echo "master ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

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

# Copy your the scripts into the container
COPY entry.sh /app/entry.sh

# Copy your Ansible playbook and inventory files into the container
COPY /master/playbooks /ansible/
COPY /master/inventory.ini /ansible/

# Make the scripts executable
RUN chmod +x /app/entry.sh

# By default, sleep to keep the container running for manual interaction
CMD ["/app/entry.sh"]
