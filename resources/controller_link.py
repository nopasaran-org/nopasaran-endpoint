import os
import random
import secrets
import subprocess
import logging
import subprocess
import sys
import asyncio
import socket
import threading
from fastapi_websocket_rpc import WebSocketRpcClient, logger
from fastapi_websocket_rpc.rpc_methods import RpcUtilityMethods
import dotenv
from certificates import get_certificates
from list_certificates import get_certificate_contents

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

    async def check_tunnel_process_async(self):
        while True:
            if self.is_running and self.process:
                return_code = self.process.poll()
                if return_code is not None:
                    self.is_running = False
                    asyncio.create_task(self.channel.other.notify_free_status())
                    logging.error(f"SSH tunnel process (PID {self.process.pid}) has exited with return code {return_code}")
                    # You can take appropriate action here, such as restarting the tunnel or handling the error.

            await asyncio.sleep(1)

    async def check_inventory_changes(self):
        current_entries = []
        while True:
            new_entries = get_changes(current_entries)
            if new_entries is not None:
                current_entries = new_entries
                asyncio.create_task(self.channel.other.notify_connected_nodes(connected_nodes=current_entries))

            await asyncio.sleep(1)  # Check every 1 second

    async def allow_exit(self):
        async def allow():
            self.can_exit.set()
        asyncio.create_task(allow())

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
            self.process = subprocess.Popen(
                tunnel_command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=False
            )

            self.is_running = True


            # Create a separate thread to run the tunnel process checker
            def tunnel_checker_thread():
                asyncio.run(self.check_tunnel_process_async())

            tunnel_checker_thread = threading.Thread(target=tunnel_checker_thread)
            tunnel_checker_thread.daemon = True  # Allow the thread to exit when the main program exits
            tunnel_checker_thread.start()

            return f"+ {ssh_manager_hostname}"
        except Exception as e:
            # Handle any errors that occur during SSH tunnel creation
            error_message = f"Error creating SSH tunnel: {e}"
            return f"- {error_message}"

    async def restart(self):
        restart_command = ["service", "ssh", "restart"]

        try:
            subprocess.Popen(
                restart_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            return f"+ {True}"
        except Exception as e:
            error_message = f"Error restarting the SSH daemon: {e}"
            return f"- {error_message}"
        
    async def free(self):
        try:
            # Use subprocess to execute the 'kill' command with the PID
            subprocess.run(["kill", str(self.process.pid)], check=True)
            self.process = None
            return f"+ {None}"
        except Exception as e:
            # Handle any errors that occur when trying to kill the process
            error_message = f"Error killing SSH tunnel process: {e}"
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
            print(certificates)
            return f"+ {certificates}"
        except Exception as e:
            return f"- {e}"
        
    async def execute_create_containers_playbook(self):
        try:
            # Execute the Ansible playbook for creating containers
            result = subprocess.run(
                ["ansible-playbook", "-i", "/ansible/inventory.ini", "/ansible/create_containers.yml"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            return f"+ {result.stdout}"
        except Exception as e:
            return f"- {str(e)}"

    async def execute_delete_containers_playbook(self):
        try:
            # Execute the Ansible playbook for deleting containers
            result = subprocess.run(
                ["ansible-playbook", "-i", "/ansible/inventory.ini", "/ansible/delete_containers.yml"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            return f"+ {result.stdout}"
        except Exception as e:
            return f"- {str(e)}"

    async def execute_campaign(self, repository="", folder_name="", variables="", hostname=""):
        try:
            final_output_directory = secrets.token_hex(6)

            # Execute the Ansible playbook for the campaign
            result = subprocess.run(
                [
                    "ansible-playbook",
                    "/ansible/remote_scenario.yml",
                    "-i",
                    "/ansible/inventory.ini",
                    "--extra-vars",
                    f'{{"github_repo_url":"{repository}", "scenario_folder":"{folder_name}", "final_output_directory":"{final_output_directory}", "variables":{variables}}}',
                    "--limit", 
                    f"{hostname}"
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            # Find log files in the specified directory tree
            log_contents = []
            for root, dirs, files in os.walk(f"/results/{final_output_directory}"):
                for file in files:
                    if file.startswith("conf") and file.endswith(".log"):
                        log_file_path = os.path.join(root, file)
                        with open(log_file_path, 'r') as log_file:
                            log_contents.append(log_file.read())

            return f"+ {', '.join(log_contents)}"  # Join log contents with a comma or any other separator
        except Exception as e:
            return f"- {str(e)}"
        

    async def configure_netbird_key(self, key_setup="", endpoint_name="", role="", server_domain_name=""):
        try:            
            # Construct the hostname
            hostname = f"{endpoint_name}.{role}.{server_domain_name}"

            # Execute the netbird up command
            result = subprocess.run(
                [
                    "netbird",
                    "up",
                    "--setup-key", key_setup,
                    "--hostname", hostname
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

# Initialize a threading event flag
inventory_update_thread_exit = threading.Event()

# Initialize a set to store the previous entries
previous_entries = set()

def load_entries(file_path):
    entries = []
    try:
        with open(file_path, 'r') as file:
            for line in file:
                # Assuming the entries are in the format "[nopasaran_nodes] hostname"
                if line.strip().startswith("[nopasaran_nodes]"):
                    continue
                entries.append(line.split()[0])
    except FileNotFoundError:
        pass  # Handle the case where the file doesn't exist
    return entries

def get_changes(previous_entries):
    current_entries = load_entries(INVENTORY_PATH)
    if current_entries != previous_entries:
        previous_entries = current_entries
        return current_entries
    
    return None

async def on_connect(channel):
    inventory_update_thread_exit.clear()
    client_private_ip = get_local_ip_for_target(host)
    netbird_ip = get_netbird_ip()
    await asyncio.create_task(channel.other.register_ip_addresses(client_private_ip=client_private_ip, netbird_ip=netbird_ip))

    if ROLE == "manager":
        # Create a separate thread to check the difference in inventory
        def inventory_update_checker(channel):
            while not inventory_update_thread_exit.is_set():
                asyncio.run(channel.methods.check_inventory_changes())
                # Sleep for a short duration before checking again
                asyncio.sleep(1)

        inventory_update_thread = threading.Thread(target=inventory_update_checker, args=(channel,))
        inventory_update_thread.daemon = True  # Allow the thread to exit when the main program exits
        inventory_update_thread.start()

async def run_client(uri):
    global previous_entries
    while True:
        try:
            async with WebSocketRpcClient(uri, ClientRPC(), on_connect=[on_connect]) as client:
                task1 = asyncio.create_task(client.channel.methods.can_exit.wait())
                task2 = asyncio.create_task(client.channel._closed.wait())

                # Wait for either the can_exit event or the WebSocket connection to close
                done, _ = await asyncio.wait([task1, task2], return_when=asyncio.FIRST_COMPLETED)

                # Set the inventory update thread exit flag when the WebSocket connection is closed
                if task2 in done:
                    inventory_update_thread_exit.set()
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