import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import datetime
import os
import sys
from urllib.parse import urljoin
import logging
import json as json_loader

import requests
import dotenv
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from utils import get_api_base_url

# Load the .env file, but don't override existing environment variables
dotenv.load_dotenv('/app/resources/config.env', override=False)

USER = "USER"
HOST = "HOST"
X509 = "X509"
OWN = "OWN"
OTHER = "OTHER"
NODE = "node"
POOL_MANAGER = "pool-manager"

# Configure the logging module
logging.basicConfig(format='%(asctime)s - %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.INFO)
logger = logging.getLogger()

# Get the directory of the current Python file
current_directory = os.path.dirname(__file__)

# Define the required environment variable names
required_env_vars = ["ENDPOINT_NAME", "AUTHORIZATION_TOKEN", "ROLE"]

# Initialize a list to store missing environment variables
missing_vars = []

# Check if all required environment variables exist and are not empty
for var_name in required_env_vars:
    var_value = os.environ.get(var_name)
    if not var_value:
        missing_vars.append(var_name)

# If any required environment variables are missing, log an error and list them
if missing_vars:
    logging.error("The following environment variables are missing or empty:")
    for var_name in missing_vars:
        logging.error(f" - {var_name}")
    sys.exit(1)

# All required environment variables are correctly loaded
logging.info("All required environment variables are correctly loaded.")

# You can access the values of the environment variables like this:
ENDPOINT_NAME = os.environ.get("ENDPOINT_NAME")
AUTHORIZATION_TOKEN = os.environ.get("AUTHORIZATION_TOKEN")
ROLE = os.environ.get("ROLE")

def generate_new_ssh_key(certificate_type, key_size=4096, exponent=65537):
    input_path = os.getenv(f'{certificate_type}_INPUT_PATH')  
    input_filename_private = os.getenv(f'{certificate_type}_INPUT_FILENAME_PRIVATE')
    input_filename_public = os.getenv(f'{certificate_type}_INPUT_FILENAME_PUBLIC')

    # Generate an RSA private key for SSH
    private_key = rsa.generate_private_key(
        public_exponent=exponent,
        key_size=key_size,
        backend=default_backend()
    )

    # Serialize the private key in PEM format and save it to a file
    private_key_ssh = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption()
    )

    save_response_to_file(private_key_ssh, input_path, input_filename_private)

    private_key_path = os.path.join(os.path.expanduser(input_path), input_filename_private)
    # Set the private key file permissions to be readable only by the owner (600)
    os.chmod(private_key_path, 0o600)

    # Extract the public key from the private key and save it to a separate file
    public_key = private_key.public_key()
    public_key_ssh = public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
    )
    
    save_response_to_file(public_key_ssh, input_path, input_filename_public)

def retrieve_ca_certificate(certificate_type):
    if ROLE in [NODE, POOL_MANAGER]:
            if certificate_type == ROLE:
                variable_certificate_suffix = OWN
            else:
                variable_certificate_suffix = OTHER
    else:
        raise ValueError("Invalid role specified. Role must be 'node' or 'pool-manager'.")
    

    # Get the API domain from the [server] section
    api_domain = get_api_base_url(os.getenv('SERVER_HOST'), os.getenv('SERVER_PORT'))

    # Construct the URL for CA certificate retrieval
    ca_url = urljoin(api_domain, os.getenv(f'API_GET_{str.upper(certificate_type).replace("-", "_")}_CA_PATH'))

    # Send a GET request to retrieve the CA certificate
    response = requests.get(ca_url)

    # Check if the request was successful
    if response.status_code == 200:
        # Save the CA certificate to the specified output path
        save_response_to_file(response.content, os.getenv(f'{variable_certificate_suffix}_CA_OUTPUT_PATH'), os.getenv(f'{variable_certificate_suffix}_CA_OUTPUT_FILENAME'))
        ca_authority_path = os.path.join(os.getenv(f'{variable_certificate_suffix}_CA_OUTPUT_PATH'), os.getenv(f'{variable_certificate_suffix}_CA_OUTPUT_FILENAME'))
        # Set the truos.path.expanduser(retrieve_ca_config["output_path"]), retrieve_ca_config["output_filename"]sted CA file permissions to be readable only by the owner (600)
        os.chmod(ca_authority_path, 0o600)
        if variable_certificate_suffix == OWN:
            update_ssh_client_config(POOL_MANAGER if ROLE == NODE else NODE)
        elif  variable_certificate_suffix == OTHER:
            domain_suffix = os.getenv('OTHER_CA_DOMAIN_SUFFIX')
            ca_authority_line = f"@cert-authority *.{certificate_type}.{domain_suffix} {response.content.decode()}\n"
            save_response_to_file(ca_authority_line.encode(), os.getenv('OTHER_CA_KNOWN_HOST_PATH'), os.getenv('OTHER_CA_KNOWN_HOST_FILENAME'))
            known_hosts_path = os.path.join(os.path.expanduser(os.getenv('OTHER_CA_KNOWN_HOST_PATH')), os.getenv('OTHER_CA_KNOWN_HOST_FILENAME'))
            # Set the known_hosts file to be readable only by the owner (600)
            os.chmod(known_hosts_path, 0o600)
    else:
        logger.error(f"Request failed with status code: {response.status_code}")
        logger.error(f"Error message: {response.text}")


def retrieve_ssh_certificate(certificate_type):
    api_domain = get_api_base_url(os.getenv('SERVER_HOST'), os.getenv('SERVER_PORT'))

    # Construct the URL based on the certificate type
    certificate_url = urljoin(api_domain, os.getenv('API_GENERATE_SSH_CERTIFICATE_PATH'))

    json = {
            "token": AUTHORIZATION_TOKEN,
            "endpoint_name": ENDPOINT_NAME
        }
    
    # Add role-specific certificate type
    if ROLE == NODE:
        json["certificate_type"] = "0" if certificate_type == USER else "1"
    elif ROLE == POOL_MANAGER:
        json["certificate_type"] = "2" if certificate_type == USER else "3"
    else:
        raise ValueError("Invalid role specified. Role must be 'node' or 'pool_manager'.")

    # Check if the 'generate' field is set to 1 to generate a new key
    if os.getenv(f'{certificate_type}_GENERATE') == "1":
        # Generate a new SSH key and set it in the headers
        generate_new_ssh_key(certificate_type)

    # Load the SSH key from the specified file
    input_path = os.getenv(f'{certificate_type}_INPUT_PATH')
    input_filename = os.getenv(f'{certificate_type}_INPUT_FILENAME_PUBLIC')

    if input_filename:
        existing_ssh_key = load_existing_file(input_path, input_filename)
        json["public_key"] = existing_ssh_key
    else:
        raise ValueError("Input filename not specified.")

    # Send the POST request with headers
    response = requests.post(certificate_url, json=json)

    # Check if the request was successful
    if response.status_code == 200:
        # Save the response content to the specified output path
        content = json_loader.loads(response.content.decode()).get("certificate").encode()
        
        save_response_to_file(content, os.getenv(f'{certificate_type}_OUTPUT_PATH'), os.getenv(f'{certificate_type}_OUTPUT_FILENAME'))
        if certificate_type == USER:
            update_sshd_config_user_certificate()
        else:
            update_sshd_config_host_certificate()
    else:
        logger.error(f"Request failed with status code: {response.status_code}")
        logger.error(f"Error message: {response.text}")

def update_ssh_client_config(host_type):
    # Retrieve values from the configuration
    domain_suffix = os.getenv('OWN_CA_DOMAIN_SUFFIX')
    private_key_path = os.getenv('USER_INPUT_PATH')
    private_key_filename = os.getenv('USER_INPUT_FILENAME_PRIVATE')
    ssh_client_config_path = os.path.expanduser(os.getenv('OWN_CA_SSH_CLIENT_CONFIG_PATH'))
    new_line = f'IdentityFile {os.path.join(os.path.expanduser(private_key_path), private_key_filename)}\n'

    # Check if the SSH client configuration file exists, and create it if it doesn't
    if not os.path.exists(ssh_client_config_path):
        os.makedirs(os.path.dirname(ssh_client_config_path), exist_ok=True)
        open(ssh_client_config_path, 'a').close()

    # Define the Host line with the specified host_type and domain suffix
    host_line = f'Host *.{host_type}.{domain_suffix}\n'

    # Read the existing SSH client configuration file
    with open(ssh_client_config_path, 'r') as file:
        lines = file.readlines()

    # Find and remove all existing Host lines
    for i, line in enumerate(lines):
        if line.startswith('Host '):
            # Remove the existing Host line
            lines.pop(i)

    # Add the Host line to the end of the file
    lines.append(host_line)

    # Check if the IdentityFile line already exists and update it if needed
    identity_file_exists = False
    for i, line in enumerate(lines):
        if line.startswith('IdentityFile '):
            lines[i] = new_line
            identity_file_exists = True
            break

    # If the IdentityFile line doesn't exist, add it to the end of the file
    if not identity_file_exists:
        lines.append(new_line)

    # Write the modified content back to the SSH client configuration file
    with open(ssh_client_config_path, 'w') as file:
        file.writelines(lines)

    logging.info(f'SSH client configuration updated for {host_type} at {ssh_client_config_path}')


def save_response_to_file(content, output_path, output_filename):
    # If the output path is empty, use the current working directory
    if not output_path:
        output_path = os.getcwd()
    
    # Expand the ~ symbol to the user's home directory
    expanded_output_path = os.path.expanduser(output_path)
    
    # Create the full output file path
    output_file_path = os.path.join(expanded_output_path, output_filename)
    
    # Ensure that the directory exists; create it if necessary
    os.makedirs(os.path.dirname(output_file_path), exist_ok=True)
    
    with open(output_file_path, "wb") as file:
        file.write(content)
    logging.info(f"File saved to {output_file_path}")

def load_existing_file(input_path, input_filename):
    # If the output path is empty, use the current working directory
    if not input_path:
        input_path = os.getcwd()
    
    # Expand the ~ symbol to the user's home directory
    expanded_input_path = os.path.expanduser(input_path)
    
    # Create the full input file path
    input_file_path = os.path.join(expanded_input_path, input_filename)

    # Load the input file
    if os.path.exists(input_file_path):
        with open(input_file_path, "r") as input_file:
            existing_input = input_file.read().strip()
        return existing_input
    else:
        raise FileNotFoundError(f"File not found: {input_file_path}")

def update_sshd_config_user_certificate():
    # Retrieve values from the configuration
    output_path = os.getenv('OTHER_CA_OUTPUT_PATH')
    output_filename = os.getenv('OTHER_CA_OUTPUT_FILENAME')
    sshd_config_path = os.getenv('USER_SSHD_CONFIG_PATH')
    new_line = f'TrustedUserCAKeys {os.path.join(output_path, output_filename)}\n'

    # Read the existing sshd_config file
    with open(sshd_config_path, 'r') as file:
        lines = file.readlines()

    # Check if the TrusedUserCAKeys line already exists and update it if needed
    user_certificate_exists = False
    for i, line in enumerate(lines):
        if line.startswith('TrustedUserCAKeys '):
            lines[i] = new_line
            user_certificate_exists = True
            break

    # If the TrustedUserCAKeys line doesn't exist, add it to the end of the file
    if not user_certificate_exists:
        lines.append(new_line)

    # Update security settings in the sshd_config file
    security_settings = [
        #'PasswordAuthentication no\n',
        'ChallengeResponseAuthentication no\n'
    ]

    for setting in security_settings:
        if setting not in lines:
            lines.append(setting)

    # Write the modified content back to the sshd_config file
    with open(sshd_config_path, 'w') as file:
        file.writelines(lines)

    logging.info(f'User certificate configuration and security settings updated in {sshd_config_path}.')

def update_sshd_config_host_certificate():
    # Retrieve values from the configuration
    output_path = os.getenv('HOST_OUTPUT_PATH')
    output_filename = os.getenv('HOST_OUTPUT_FILENAME')
    sshd_config_path = os.getenv('HOST_SSHD_CONFIG_PATH')
    new_line = f'HostCertificate {os.path.join(output_path, output_filename)}\n'

    # Read the existing sshd_config file
    with open(sshd_config_path, 'r') as file:
        lines = file.readlines()

    # Check if the HostCertificate line already exists and update it if needed
    host_certificate_exists = False
    for i, line in enumerate(lines):
        if line.startswith('HostCertificate '):
            lines[i] = new_line
            host_certificate_exists = True
            break

    # If the HostCertificate line doesn't exist, add it to the end of the file
    if not host_certificate_exists:
        lines.append(new_line)

    # Write the modified content back to the sshd_config file
    with open(sshd_config_path, 'w') as file:
        file.writelines(lines)

    logging.info(f'HostCertificate line updated or added to {sshd_config_path}')

def main():
    parser = argparse.ArgumentParser(description="Retrieve certificates using a configuration file.")
    parser.add_argument("--log-file", default="system.log", help="Path to the log file")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                        help="Set the logging level")
    parser.add_argument("--num-threads", type=int, default=4, help="Number of threads for parallel execution")
    args = parser.parse_args()

    # Set the logging level
    logging_level = getattr(logging, args.log_level)
    logger.setLevel(logging_level)

    # Create a formatter to include timestamps
    formatter = logging.Formatter('%(asctime)s - %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

    # Create a file handler for the log file
    file_handler = logging.FileHandler(args.log_file)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    # Log a timestamp
    logger.info("Script started at %s", datetime.datetime.now())

    # List of tasks for certificate retrieval
    tasks = []
    with ThreadPoolExecutor(max_workers=args.num_threads) as executor:
        # Example usage to retrieve a user certificate
        tasks.append(executor.submit(retrieve_ssh_certificate, USER))

        # Example usage to retrieve a host certificate
        tasks.append(executor.submit(retrieve_ssh_certificate, HOST))

        # Example usage to retrieve a node CA certificate
        tasks.append(executor.submit(retrieve_ca_certificate, NODE))

        # Example usage to retrieve a pool_manager CA certificate
        tasks.append(executor.submit(retrieve_ca_certificate, POOL_MANAGER))


    # Handle errors and exceptions
    for task in as_completed(tasks):
        try:
            task.result()
        except Exception as e:
            logger.error(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    main()
