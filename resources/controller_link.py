import os
import subprocess
import logging
import subprocess
import sys
import asyncio
import socket

from fastapi_websocket_rpc import WebSocketRpcClient, logger
from fastapi_websocket_rpc.rpc_methods import RpcUtilityMethods
import dotenv
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from certificates import get_certificates
from list_certificates import get_certificate_contents
from decision_tree import DecisionTree, download_png_by_name, fetch_png_files_from_github

# Load the .env file, but don't override existing environment variables
dotenv.load_dotenv('/app/resources/config.env', override=False)

logger.logging_config.set_mode(logger.LoggingModes.UVICORN, logger.logging.DEBUG)

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

# Initialize default host and port values
host = os.getenv('SERVER_HOST')
port = int(os.getenv('SERVER_PORT'))


# You can access the values of the environment variables like this:
ENDPOINT_NAME = os.environ.get("ENDPOINT_NAME")
AUTHORIZATION_TOKEN = os.environ.get("AUTHORIZATION_TOKEN")
ROLE = os.environ.get("ROLE")

# Define the output file path
INVENTORY_PATH = os.path.expanduser(os.getenv("INVENTORY_PATH"))

import subprocess
import re

def encrypt(domain, key="NOT_SECRET"):
    # Generate a random nonce for CTR mode
    nonce = os.urandom(16)
    # Ensure the key is 16 bytes long (AES-128 requires 16-byte key)
    aes_key = key.ljust(16, '\0')[:16].encode('utf-8')
    cipher = Cipher(algorithms.AES(aes_key), modes.CTR(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_bytes = nonce + encryptor.update(domain.encode('utf-8')) + encryptor.finalize()
    return encrypted_bytes

def to_custom_base(encrypted_bytes):
    base_characters = 'abcdefghijklmnop'
    base_str = ''
    for byte in encrypted_bytes:
        high_nibble = (byte >> 4) & 0xF
        low_nibble = byte & 0xF
        base_str += base_characters[high_nibble] + base_characters[low_nibble]
    return base_str

def from_custom_base(base_str):
    base_characters = 'abcdefghijklmnop'
    base_map = {char: index for index, char in enumerate(base_characters)}
    encrypted_bytes = bytearray()
    for i in range(0, len(base_str), 2):
        high_nibble = base_map[base_str[i]]
        low_nibble = base_map[base_str[i+1]]
        byte = (high_nibble << 4) | low_nibble
        encrypted_bytes.append(byte)
    return encrypted_bytes

def decrypt(encrypted_bytes, key="NOT_SECRET"):
    nonce = encrypted_bytes[:16]
    ciphertext = encrypted_bytes[16:]
    aes_key = key.ljust(16, '\0')[:16].encode('utf-8')
    cipher = Cipher(algorithms.AES(aes_key), modes.CTR(nonce), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_bytes = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_bytes.decode('utf-8')


def get_netbird_ip():
    try:
        # Run the netbird status command and capture its output
        result = subprocess.run(['netbird', 'status'], capture_output=True, text=True, check=True)

        # Extract NetBird IP using regex
        output = result.stdout.strip()
        ip_match = re.search(r'NetBird IP: (\d+\.\d+\.\d+\.\d+)', output)
        if ip_match:
            return ip_match.group(1)
        else:
            return None
    
    except subprocess.CalledProcessError:
        # If the command fails, return None
        return None


# Methods to expose to the clients
class ClientRPC(RpcUtilityMethods):
    def __init__(self):
        super().__init__()
        self.process = None
        self.is_running = False
        self.can_exit = asyncio.Event()

    async def allow_exit(self):
        async def allow():
            self.can_exit.set()
        asyncio.create_task(allow())

    async def restart(self):
        try:
            # Start netbird service
            netbird_command = ["netbird", "service", "start"]
            subprocess.Popen(
                netbird_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            ).communicate()  # Ensure this completes before proceeding
            
            # Restart ssh service
            ssh_command = ["service", "ssh", "restart"]
            subprocess.Popen(
                ssh_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            ).communicate()  # Ensure this completes before proceeding

            return f"+ {True}"
        except Exception as e:
            error_message = f"Error restarting the services: {e}"
            return f"- {error_message}"

    async def generate_certificates_and_restart(self):
        try:
            # Call the functions to generate certificates
            result = get_certificates()

            # Restart the machine
            restart_command = ["service", "ssh", "restart"]
            subprocess.run(restart_command, check=True)

            return f"+ {result}"
        except Exception as e:
            return f"- {str(e)}"
        
    async def list_certificates(self):
        try:
            certificates = get_certificate_contents()
            return f"+ {certificates}"
        except Exception as e:
            return f"- {e}"

    async def execute_campaign(self, repository="", campaign="", nodes="", variables=""):
        try:
            campaign_files = fetch_png_files_from_github(repository)
            campaign_content = download_png_by_name(campaign_files, campaign)
            tree = DecisionTree()
            tree.load_from_png_content(campaign_content)
            final_output = tree.evaluate_tree(variables)
            return f"+ {final_output}"
        except Exception as e:
            return f"- {str(e)}"

    async def configure_netbird_key(self, key_setup="", endpoint_name="", owner_username="", role="", server_domain_name=""):
        try:            
            # Construct the hostname
            hostname = f"{endpoint_name}.{owner_username}.{role}.{server_domain_name}"

            # Execute the netbird up command
            result = subprocess.run(
                [
                    "netbird",
                    "up",
                    "--setup-key", key_setup,
                    "--hostname", to_custom_base(encrypt(hostname))
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            # Check if there are any errors
            if result.returncode != 0:
                return f"- Error: {result.stderr}"

            return f"+ Done"  # Join log contents with a comma or any other separator
        except Exception as e:
            return f"- {str(e)}"


def get_local_ip_for_target(target_ip):
    try:
        # Create a socket object with SOCK_DGRAM (UDP) type.
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # Connect the socket to the target IP on an arbitrary port (doesn't establish a connection).
        s.connect((target_ip, 1))
        
        # Get the local IP address associated with the socket.
        local_ip = s.getsockname()[0]
        
        # Close the socket.
        s.close()
        
        return local_ip
    except Exception as e:
        print(f"Error: {e}")
        return None


async def on_connect(channel):
    client_private_ip = get_local_ip_for_target(host)
    netbird_ip = get_netbird_ip()
    await asyncio.create_task(channel.other.register_ip_addresses(client_private_ip=client_private_ip, netbird_ip=netbird_ip))

async def run_client(uri):
    while True:
        try:
            async with WebSocketRpcClient(uri, ClientRPC(), on_connect=[on_connect]) as client:
                task1 = asyncio.create_task(client.channel.methods.can_exit.wait())
                task2 = asyncio.create_task(client.channel._closed.wait())

                # Wait for either the can_exit event or the WebSocket connection to close
                await asyncio.wait([task1, task2], return_when=asyncio.FIRST_COMPLETED)

        except Exception as e:
            print(f"Error: {e}")
            await asyncio.sleep(3)  # Retry every 3 seconds


def main():
    # Determine the scheme (HTTP or HTTPS) based on the port number.
    scheme = "wss" if port == 443 else "ws"

    # Use a lambda function to pass token and endpoint_name as query parameters
    uri_with_params = f"{scheme}://{host}:{port}/ws/endpoints?token={AUTHORIZATION_TOKEN}&endpoint_name={ENDPOINT_NAME}"

    asyncio.get_event_loop().run_until_complete(run_client(uri_with_params))

if __name__ == '__main__':
    main()