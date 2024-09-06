import os
import subprocess
import logging
import sys
import asyncio
import socket
import pickle
import base64

from websockets.exceptions import ConnectionClosedOK
from fastapi_websocket_rpc import WebSocketRpcClient, logger
from fastapi_websocket_rpc.rpc_methods import RpcUtilityMethods
import dotenv

from certificates import get_certificates
from list_certificates import get_certificates_list
from task_publisher import init_publisher, publish_task, read_results

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

init_publisher()

import subprocess
import re

# Add an async function to read results periodically and send them to the WebSocket channel
async def periodic_result_reader(channel, interval=5):
    while True:
        try:
            # Read the results of the tests-trees
            results = read_results()
            # If results are found, send them to the WebSocket channel
            if results:
                await channel.other.signal_task_done(results=results)
                logging.info(f"Results sent to the coordinator")
        except FileNotFoundError:
            # No result file found, you can log it or ignore silently
            logging.info(f"No result file found, retrying in {interval} seconds.")
        except Exception as e:
            # Log any other errors
            logging.error(f"Error reading results: {e}")
        
        # Wait for the specified interval before checking again
        await asyncio.sleep(interval)
        
def restart_daemons():        
    try:
        # Attempt to restart the SSH daemon
        logging.info("Attempting to restart the netbird daemon...")
        netbird_command = ["netbird", "service", "start"]
        subprocess.Popen(
            netbird_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        ).communicate()  # Ensure this completes before proceeding
        # Log success
        logging.info("Netbird daemon restarted successfully.")
        
        # Attempt to restart the SSH daemon
        logging.info("Attempting to restart the netbird daemon...")
        # Restart ssh service
        ssh_command = ["service", "ssh", "restart"]
        subprocess.Popen(
            ssh_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        ).communicate()  # Ensure this completes before proceeding
        # Log success
        logging.info("SSH daemon restarted successfully.")

    except Exception as e:
        # Log failure with error details
        logging.error(f"Failed to restart the daemons: {e}")

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
    
def configure_netbird_key(setup_key, hostname):
    try:            
        # Execute the netbird up command
        subprocess.run(
            [
                "netbird",
                "up",
                "--setup-key", setup_key,
                "--hostname", hostname
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
    except Exception as e:
        logging.error(f"Error: {e}")


# Methods to expose to the clients
class ClientRPC(RpcUtilityMethods):
    def __init__(self):
        super().__init__()
        self.process = None
        self.is_running = False
        self.can_exit = asyncio.Event()

    @staticmethod
    def encode(data):
        serialized_obj = pickle.dumps(data)
        encoded_data = base64.b64encode(serialized_obj).decode('utf-8')  
        return encoded_data      
        
    @staticmethod
    def decode(encoded_data):
        serialized_obj = base64.b64decode(encoded_data)
        data = pickle.loads(serialized_obj)
        return data

    async def allow_exit(self):
        async def allow():
            self.can_exit.set()
        asyncio.create_task(allow())

    async def restart(self):
        restart_daemons()

    async def execute_task(self, task_id="", repository="", tests_tree="", nodes="", variables=""):
        try:
            publish_task(task_id, repository, tests_tree, nodes, variables)
            return f"+ Submitted"
        except Exception as e:
            return f"- {str(e)}"

def generate_certificates():
        certificates_list = get_certificates_list()
        if False in certificates_list:
            # Call the functions to generate certificates
            get_certificates()
            return True
        else:
            return False


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
        logging.error(f"Error: {e}")
        return None


async def on_connect(channel):
    need_restart = generate_certificates()
    
    hostname_response = await asyncio.create_task(channel.other.get_hostname()) 
    hostname = ClientRPC.decode(hostname_response.result)
    
    endpoint_response = await asyncio.create_task(channel.other.get_endpoint()) 
    endpoint = ClientRPC.decode(endpoint_response.result)
    
    configure_netbird_key(endpoint['mesh_key_setup'], hostname)
    
    netbird_ip = get_netbird_ip()
    client_private_ip = get_local_ip_for_target(host)
    
    if netbird_ip is None:
        setup_key_response = await asyncio.create_task(channel.other.update_setup_key()) 
        setup_key = ClientRPC.decode(setup_key_response.result)
        logging.error(setup_key)
        if setup_key:
            configure_netbird_key(setup_key, hostname)
            
    if netbird_ip is None or need_restart:
       restart_daemons()
    else:
       ips = ClientRPC.encode({
           "netbird_ip": netbird_ip, 
           "client_private_ip": client_private_ip
           })
       await asyncio.create_task(channel.other.set_ips(ips=ips)) 

async def run_client(uri):
    while True:
        try:
            async with WebSocketRpcClient(uri, ClientRPC(), on_connect=[on_connect]) as client:
                # Create the periodic result reader task
                result_reader_task = asyncio.create_task(periodic_result_reader(client.channel))

                # Task to wait for can_exit event or connection close
                task1 = asyncio.create_task(client.channel.methods.can_exit.wait())
                task2 = asyncio.create_task(client.channel._closed.wait())

                # Wait for either the can_exit event, WebSocket connection to close, or result reader task to finish
                await asyncio.wait([task1, task2], return_when=asyncio.FIRST_COMPLETED)

                # If either of the main tasks is done, cancel the result reader
                result_reader_task.cancel()

        except Exception as e:
            logging.error(f"Error: {e}")
            await asyncio.sleep(3)  # Retry every 3 seconds


def main():
    # Determine the scheme (HTTP or HTTPS) based on the port number.
    scheme = "wss" if port == 443 else "ws"

    # Use a lambda function to pass token and endpoint_name as query parameters
    uri_with_params = f"{scheme}://{host}:{port}/ws/endpoints?token={AUTHORIZATION_TOKEN}&endpoint_name={ENDPOINT_NAME}"

    asyncio.get_event_loop().run_until_complete(run_client(uri_with_params))

if __name__ == '__main__':
    main()