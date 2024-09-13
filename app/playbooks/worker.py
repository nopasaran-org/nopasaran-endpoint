import os
import ssl
import socket
import subprocess
import json
import re
import logging
import sys
import dotenv

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Server details
HOST = '0.0.0.0'
PORT = 1957

# Load the .env file, but don't override existing environment variables
dotenv.load_dotenv('/app/resources/config.env', override=False)

# Get the server domain name from the environment
domain_name = os.getenv('SERVER_DOMAIN_NAME')

# Retrieve values of environment variables
X509_PATH = os.getenv("X509_PATH")
X509_FILENAME_CA = os.getenv("X509_FILENAME_CA")
X509_FILENAME_CERTIFICATE = os.getenv("X509_FILENAME_CERTIFICATE")
X509_FILENAME_PRIVATE = os.getenv("X509_FILENAME_PRIVATE")

# Paths to the certificates and keys
CA_CERT = os.path.join(X509_PATH, X509_FILENAME_CA)
SERVER_CERT = os.path.join(X509_PATH, X509_FILENAME_CERTIFICATE)
SERVER_KEY = os.path.join(X509_PATH, X509_FILENAME_PRIVATE)

# Regex pattern to match the domain format *.*.master.domain_name
domain_pattern = re.compile(rf".*?\..*?\.master\.{re.escape(domain_name)}")

# Validate client certificate's CN or SAN
def validate_client_certificate(cert):
    subject = dict(x[0] for x in cert.get('subject', []))
    cn = subject.get('commonName')
    logging.debug(f"Validating CN: {cn}")
    
    if cn and domain_pattern.match(cn):
        logging.debug(f"CN {cn} matches domain pattern")
        return True
    else:
        logging.debug(f"CN {cn} does not match domain pattern")
    
    san = cert.get('subjectAltName', [])
    for name_type, san_value in san:
        logging.debug(f"Validating SAN: {san_value}")
        if name_type == 'DNS' and domain_pattern.match(san_value):
            logging.debug(f"SAN {san_value} matches domain pattern")
            return True
    
    logging.debug(f"Client certificate validation failed")
    return False

# Command execution logic (unchanged)
def handle_client(conn):
    try:
        # Receive the length of the message first
        length_data = conn.recv(4)
        if not length_data:
            return
        length = int.from_bytes(length_data, byteorder='big')

        # Receive the actual message data
        data = b''
        while len(data) < length:
            packet = conn.recv(length - len(data))
            if not packet:
                break
            data += packet
        
        if not data:
            return
        
        # Decode and parse the JSON data
        data = data.decode('utf-8')
        
        # Parse the JSON data
        data_dict = json.loads(data)
        repository = data_dict.get('repository')
        test_folder = data_dict.get('test_folder')
        control_node = data_dict.get('control_node')
        variables = data_dict.get('variables')
        control_port = data_dict.get('control_port')

        # Define random folder name
        random_folder_name = f"nopasaran_{subprocess.getoutput('date +%Y%m%dT%H%M%S.%6N')}_{subprocess.getoutput('head /dev/urandom | tr -dc A-Za-z0-9 | head -c 12')}"
        base_path = f"/tmp/{random_folder_name}"
        test_full_path = f"{base_path}/{test_folder}"

        # Clone the repository
        subprocess.run(f"git clone --depth 1 -b main {repository} {base_path}", shell=True)

        # Save variables.json if provided
        if variables:
            with open(f"{test_full_path}/variables.json", 'w') as var_file:
                json.dump(variables, var_file)

        # Create the controller configuration file
        config_content = f'''
        {{
          "ROOT_CERTIFICATE": "/x509/ca.pem",
          "PRIVATE_CERTIFICATE": "/x509/private_crt.pem",
          "DESTINATION_IP": "{control_node}",
          "SERVER_PORT": "{control_port}"
        }}
        '''
        with open(f"{test_full_path}/controller_configuration.json", 'w') as config_file:
            config_file.write(config_content)

        # Run the required preprocessing if necessary
        if os.path.exists(f"{test_full_path}/variables.json"):
            subprocess.run(f"python /app/required_processing/preprocessing.py {test_full_path}/variables.json", shell=True, cwd=test_full_path)

        # Execute the nopasaran test
        subprocess.run(
            f"nopasaran -t MAIN.json -ll info",
            shell=True,
            cwd=test_full_path
        )

        # Run postprocessing
        subprocess.run("python /app/required_processing/postprocessing.py", shell=True, cwd=test_full_path)

        # Return the log file path to the client
        log_file_path = f"{test_full_path}/conf.log"
        if os.path.exists(log_file_path):
            with open(log_file_path, 'r') as log_file:
                conn.sendall(log_file.read().encode('utf-8'))
        else:
            conn.sendall(b"Log file not found.")
    finally:
        conn.close()

# Daemonize the process
def daemonize():
    logging.info("Daemonizing the server process")
    if os.fork() > 0:
        sys.exit(0)  # Exit parent process

    os.setsid()  # Create a new session
    if os.fork() > 0:
        sys.exit(0)  # Exit first child

    # Redirect standard file descriptors
    sys.stdout.flush()
    sys.stderr.flush()
    with open('/dev/null', 'r') as devnull:
        os.dup2(devnull.fileno(), sys.stdin.fileno())
    with open('/dev/null', 'a+') as devnull:
        os.dup2(devnull.fileno(), sys.stdout.fileno())
        os.dup2(devnull.fileno(), sys.stderr.fileno())
    
    logging.info("Server daemonized successfully")

# Setup SSL server
def start_server():
    logging.info("Starting SSL server setup")
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY)
    context.load_verify_locations(cafile=CA_CERT)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((HOST, PORT))
        sock.listen(5)
        logging.info(f"Server listening on {HOST}:{PORT}")
        with context.wrap_socket(sock, server_side=True) as ssock:
            while True:
                logging.debug("Waiting for a client connection")
                try:
                    client_socket, addr = ssock.accept()
                    logging.info(f"Accepted connection from {addr}")

                    # Validate the client certificate
                    client_cert = client_socket.getpeercert()
                    if not validate_client_certificate(client_cert):
                        logging.warning(f"Client {addr} failed certificate validation")
                        client_socket.close()  # Close connection and continue serving other clients
                        continue

                    logging.info(f"Client {addr} passed certificate validation")

                    pid = os.fork()  # Fork the process to handle the client
                    if pid == 0:  # Child process
                        logging.debug(f"Forked child process for {addr}, PID: {os.getpid()}")
                        ssock.close()  # Child doesn't need the listening socket
                        handle_client(client_socket)
                        sys.exit(0)  # Exit after handling the client
                    else:
                        logging.debug(f"Forked child process with PID {pid} to handle {addr}")
                        client_socket.close()  # Parent closes the connected socket
                except Exception as e:
                    logging.error(f"Error handling connection: {e}")

if __name__ == "__main__":
    daemonize()  # Daemonize the server
    start_server()
