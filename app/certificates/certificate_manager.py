import os
import logging
import dotenv
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from urllib.parse import urljoin
import requests
import json as json_loader

from certificates.file_handler import FileHandler

# Load the .env file, but don't override existing environment variables
dotenv.load_dotenv('/app/resources/config.env', override=False)

# Set up logging
logging.basicConfig(format='%(asctime)s - %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.INFO)



class CertificateManager:
    """Class to handle x509 certificate generation, CSR, and retrieval."""

    def __init__(self, hostname):
        self.hostname = hostname
        self.api_domain = self._get_api_domain(host=os.getenv('SERVER_HOST'), port=os.getenv('SERVER_PORT'))
        self.auth_token = os.getenv('AUTHORIZATION_TOKEN')
        self.endpoint_name = os.getenv('ENDPOINT_NAME')
        self.x509_path = os.getenv('X509_PATH')
        self.private_key_file = os.getenv('X509_FILENAME_PRIVATE')
        self.csr_file = os.getenv('X509_FILENAME_CSR')
        self.cert_file = os.getenv('X509_FILENAME_CERTIFICATE')
        self.ca_cert_file = os.getenv('X509_FILENAME_CA')

    def _get_api_domain(self, host, port):
        scheme = "https" if port == "443" else "http"
        return  f"{scheme}://{host}:{port}/"

    def generate_private_key(self, key_size=4096, exponent=65537):
        private_key = rsa.generate_private_key(public_exponent=exponent, key_size=key_size, backend=default_backend())
        private_key_x509 = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        FileHandler.save_to_file(private_key_x509, self.x509_path, self.private_key_file)

    def generate_csr(self):
        private_key_path = os.path.join(self.x509_path, self.private_key_file)
        with open(private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())

        csr = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self.hostname)])
        ).sign(private_key, hashes.SHA256(), default_backend())

        csr_pem = csr.public_bytes(serialization.Encoding.PEM)
        FileHandler.save_to_file(csr_pem, self.x509_path, self.csr_file)
        return csr_pem

    def retrieve_certificate(self):
        self._retrieve_ca_certificate()
        self.generate_private_key()
        csr_pem = self.generate_csr().decode('utf-8')

        cert_url = urljoin(self.api_domain, os.getenv('API_GENERATE_X509_CERTIFICATE_PATH'))
        json_data = {
            "token": self.auth_token,
            "endpoint_name": self.endpoint_name,
            "csr_pem": csr_pem
        }

        response = requests.post(cert_url, json=json_data)
        if response.status_code == 200:
            content = json_loader.loads(response.content.decode()).get("certificate").encode()
            FileHandler.save_to_file(content, self.x509_path, self.cert_file)
            self.create_private_certificate_chain()
        else:
            logging.error(f"Failed to retrieve certificate: {response.status_code} - {response.text}")

    def create_private_certificate_chain(self):
        cert_path = os.path.join(self.x509_path, self.cert_file)
        private_path = os.path.join(self.x509_path, self.private_key_file)
        chain_file_path = os.path.join(self.x509_path, os.getenv('X509_FILENAME_PRIVATE_CRT'))

        with open(cert_path, 'r') as cert_file:
            certificate_content = cert_file.read()

        with open(private_path, 'r') as private_file:
            private_content = private_file.read()

        private_cert_chain = private_content + certificate_content
        with open(chain_file_path, 'w') as chain_file:
            chain_file.write(private_cert_chain)

        logging.info(f"Private certificate chain created at {chain_file_path}")

    def _retrieve_ca_certificate(self):
        ca_url = urljoin(self.api_domain, os.getenv('API_GET_X509_CA_PATH'))
        response = requests.get(ca_url)
        if response.status_code == 200:
            FileHandler.save_to_file(response.content, self.x509_path, self.ca_cert_file)
        else:
            logging.error(f"Failed to retrieve CA certificate: {response.status_code} - {response.text}")