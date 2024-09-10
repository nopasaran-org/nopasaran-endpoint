import ssl
import socket
import json
import logging
import dotenv
import os

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load the .env file, but don't override existing environment variables
dotenv.load_dotenv('/app/resources/config.env', override=False)

# Retrieve values of environment variables
X509_PATH = os.getenv("X509_PATH")
X509_FILENAME_CA = os.getenv("X509_FILENAME_CA")
X509_FILENAME_CERTIFICATE = os.getenv("X509_FILENAME_CERTIFICATE")
X509_FILENAME_PRIVATE = os.getenv("X509_FILENAME_PRIVATE")

# Paths to the certificates and keys
CA_CERT = os.path.join(X509_PATH, X509_FILENAME_CA)
CLIENT_CERT = os.path.join(X509_PATH, X509_FILENAME_CERTIFICATE)
CLIENT_KEY = os.path.join(X509_PATH, X509_FILENAME_PRIVATE)

def start_client(server_host, server_port, data):
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_CERT)
    context.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)

    with socket.create_connection((server_host, server_port)) as sock:
        with context.wrap_socket(sock, server_hostname=server_host) as ssock:
            logging.info(f"Connected to {server_host}:{server_port}")

            # Convert the data dictionary to a JSON string
            json_data = json.dumps(data)
            length = len(json_data)

            # Send the length of the message first
            ssock.sendall(length.to_bytes(4, byteorder='big'))

            # Send the actual message data
            ssock.sendall(json_data.encode('utf-8'))

            # Receive and print the log file content
            response = ssock.recv(4096)

            return response.decode('utf-8')
