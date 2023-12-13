import os
import random
import subprocess
import logging
import subprocess
import sys
import asyncio
import socket
from fastapi_websocket_rpc import WebSocketRpcClient, logger
from fastapi_websocket_rpc.rpc_methods import RpcUtilityMethods
import dotenv
from certificates import get_certificates

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

print(os.getenv('SERVER_HOST'))

# Initialize default host and port values
host = os.getenv('SERVER_HOST')
port = int(os.getenv('SERVER_PORT'))


# You can access the values of the environment variables like this:
ENDPOINT_NAME = os.environ.get("ENDPOINT_NAME")
AUTHORIZATION_TOKEN = os.environ.get("AUTHORIZATION_TOKEN")
ROLE = os.environ.get("ROLE")

job_pid = None

# Methods to expose to the clients
class ClientRPC(RpcUtilityMethods):
    def __init__(self):
        super().__init__()
        self.can_exit = asyncio.Event()
        

    async def allow_exit(self):
        async def allow():
            self.can_exit.set()
        asyncio.create_task(allow())

    async def execute_command(self, command=""):
        try:
            result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            return result.returncode, result.stdout, result.stderr
        except Exception as e:
            return -1, None, str(e)

    async def create_ssh_tunnel(self, ssh_node_hostname="", ssh_manager_hostname="", ssh_port="", ssh_username=""):
        # Generate a random port between 20000 and 30000
        random_port = random.randint(20000, 30000)

        # Construct the SSH tunnel command
        tunnel_command = [
            "ssh",
            "-R", f"{ssh_node_hostname}:{random_port}:localhost:{1963}",
            "-N",  # No command execution
            "-p", ssh_port,  # SSH port
            "-l", ssh_username,  # SSH username
            ssh_manager_hostname  # SSH host
        ]

        try:
            # Start the SSH tunnel as a background process
            process = subprocess.Popen(
                tunnel_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            job_pid = process.pid

            asyncio.create_task(self.channel.other.notify_current_job(pid=job_pid))
            return True
        except Exception as e:
            # Handle any errors that occur during SSH tunnel creation
            error_message = f"Error creating SSH tunnel: {e}"
            asyncio.create_task(self.channel.other.notify_current_job(pid=job_pid))
            return None, error_message
        
    async def restart(self):
        # Construct the SSH tunnel command
        restart_command = ["service", "ssh", "restart"]

        try:
            # Start the SSH tunnel as a background process
            subprocess.Popen(
                restart_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            return True
        except Exception as e:
            # Handle any errors that occur during SSH tunnel creation
            error_message = f"Error creating SSH tunnel: {e}"
            return None, error_message
        
    async def free(self):
        try:
            # Use subprocess to execute the 'kill' command with the PID
            subprocess.run(["kill", str(job_pid)], check=True)
            job_pid = None
            asyncio.create_task(self.channel.other.notify_current_job(pid=job_pid))
            return True
        except Exception as e:
            # Handle any errors that occur when trying to kill the process
            error_message = f"Error killing SSH tunnel process: {e}"
            job_pid = None
            asyncio.create_task(self.channel.other.notify_current_job(pid=job_pid))
            return error_message

    async def generate_certificates_and_restart(self):
        try:
            # Call the functions to generate certificates
            result = get_certificates()

            # Restart the machine
            restart_command = ["service", "ssh", "restart"]
            subprocess.run(restart_command, check=True)

            return result
        except Exception as e:
            return str(e)

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
    asyncio.create_task(channel.other.register_private_ip(client_private_ip=client_private_ip))
    asyncio.create_task(channel.other.notify_current_job(pid=job_pid))

async def run_client(uri):
    while True:
        try:
            async with WebSocketRpcClient(uri, ClientRPC(), on_connect=[on_connect]) as client:
                task1 = asyncio.create_task(client.channel.methods.can_exit.wait())
                task2 = asyncio.create_task(client.channel._closed.wait())

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