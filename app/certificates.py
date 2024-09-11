import os
from urllib.parse import urljoin
import logging
import json as json_loader

import requests
import dotenv
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from config import get_env_variable
from utils.api_utils import get_api_base_url

# Load the .env file, but don't override existing environment variables
dotenv.load_dotenv('/app/resources/config.env', override=False)

# Configure the logging module
logging.basicConfig(format='%(asctime)s - %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.INFO)

# Get the directory of the current Python file
current_directory = os.path.dirname(__file__)

AUTHORIZATION_TOKEN = get_env_variable('AUTHORIZATION_TOKEN')
ENDPOINT_NAME = get_env_variable('ENDPOINT_NAME')
ROLE = os.environ.get("ROLE")

def generate_new_x509_key(key_size=4096, exponent=65537):
    input_path = os.getenv('X509_PATH')
    input_filename_private = os.getenv('X509_FILENAME_PRIVATE')


    # Generate an RSA private key for X509
    private_key = rsa.generate_private_key(
        public_exponent=exponent,
        key_size=key_size,
        backend=default_backend()
    )

    # Serialize the private key in PEM format and save it to a file
    private_key_x509 = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption()
        )

    save_response_to_file(private_key_x509, input_path, input_filename_private)

def generate_new_x509_csr(common_name):
    input_path = os.getenv('X509_PATH')
    input_filename_private = os.getenv('X509_FILENAME_PRIVATE')
    input_filename_csr = os.getenv('X509_FILENAME_CSR')

    # Construct the full path to the private key file
    private_key_path = os.path.join(input_path, input_filename_private)

    # Load the private key
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    # Create the CSR
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
    ).sign(private_key, hashes.SHA256(), default_backend())

    # Serialize the CSR to PEM format
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)

    # Save the CSR to file
    save_response_to_file(csr_pem, input_path, input_filename_csr)
    return csr

def retrieve_x509_certificate():
    # Retrieve the x509 CA certificate
    retrieve_x509_ca_certificate()
    
    api_domain = get_api_base_url(os.getenv('SERVER_HOST'), os.getenv('SERVER_PORT'))

    # Construct the URL based on the certificate type
    certificate_url = urljoin(api_domain, os.getenv('API_GENERATE_X509_CERTIFICATE_PATH'))

    json = {
            "token": AUTHORIZATION_TOKEN,
            "endpoint_name": ENDPOINT_NAME
        }
    
    # Check if the 'generate' field is set to 1 to generate a new key
    if os.getenv(f'X509_GENERATE') == "1":
        # Generate a new SSH key and set it in the headers
        generate_new_x509_key()


    fqdn_url = urljoin(api_domain, os.getenv('API_GET_FQDN'))
    fqdn_response = requests.get(fqdn_url, json=json) 
    # Check if the request was successful
    if fqdn_response.status_code == 200:
        fqdn = json_loader.loads(fqdn_response.content.decode()).get("fqdn")
        logging.info(f"FQDN retrieved: {fqdn}")
    else:
        logging.error(f"Request failed with status code: {fqdn_response.status_code}")
        logging.error(f"Error message: {fqdn_response.text}")

    csr = generate_new_x509_csr(common_name=fqdn)
    csr_pem = csr.public_bytes(Encoding.PEM).decode('utf-8')
    json["csr_pem"] = csr_pem

    # Send the POST request with headers
    response = requests.post(certificate_url, json=json)

    # Check if the request was successful
    if response.status_code == 200:
        content = json_loader.loads(response.content.decode()).get("certificate").encode()
        save_response_to_file(content, os.getenv('X509_PATH'), os.getenv('X509_FILENAME_CERTIFICATE'))
        create_x509_private_certificate()
    else:
        logging.error(f"Request failed with status code: {response.status_code}")
        logging.error(f"Error message: {response.text}")

def create_x509_private_certificate():
    # Get environment variables
    x509_folder_path = os.getenv('X509_PATH')
    x509_certificate_filename = os.getenv('X509_FILENAME_CERTIFICATE')
    x509_private_filename = os.getenv('X509_FILENAME_PRIVATE')
    x509_private_crt_filename = os.getenv('X509_FILENAME_PRIVATE_CRT')

    # Construct full file paths
    certificate_path = os.path.join(x509_folder_path, x509_certificate_filename)
    private_path = os.path.join(x509_folder_path, x509_private_filename)
    private_crt_path = os.path.join(x509_folder_path, x509_private_crt_filename)

    # Read the certificate file
    with open(certificate_path, 'r') as cert_file:
        certificate_content = cert_file.read()

    # Read the CA file
    with open(private_path, 'r') as private_file:
        private_content = private_file.read()

    # Concatenate the certificate and CA contents
    private_crt_content = private_content + certificate_content

    # Write the concatenated content to the chain file
    with open(private_crt_path, 'w') as private_crt_file:
        private_crt_file.write(private_crt_content)

    logging.info(f"Certificate chain created at {private_crt_path}")

def retrieve_x509_ca_certificate():    
    # Get the API domain from the [server] section
    api_domain = get_api_base_url(os.getenv('SERVER_HOST'), os.getenv('SERVER_PORT'))

    # Construct the URL for CA certificate retrieval
    ca_url = urljoin(api_domain, os.getenv('API_GET_X509_CA_PATH'))

    # Send a GET request to retrieve the CA certificate
    response = requests.get(ca_url)

    # Check if the request was successful
    if response.status_code == 200:
        # Save the CA certificate to the specified output path
        save_response_to_file(response.content, os.getenv('X509_PATH'), os.getenv('X509_FILENAME_CA'))
    else:
        logging.error(f"Request failed with status code: {response.status_code}")
        logging.error(f"Error message: {response.text}")

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

def get_certificates():
    success = True
    # Handle errors and exceptions
    try:
        retrieve_x509_certificate()
    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
        success = False
    return success