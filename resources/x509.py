import logging
import argparse
import datetime
import os
from configparser import ConfigParser
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption


def generate_private_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

def create_csr(private_key, common_name):
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
    ).sign(private_key, hashes.SHA256(), default_backend())
    return csr

def sign_csr_with_ca(csr, ca_private_key, ca_certificate):
    signed_cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_certificate.subject)
        .public_key(csr.public_key())
        .serial_number(1000)
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .sign(
            private_key=ca_private_key,
            algorithm=hashes.SHA256(),
            backend=default_backend()
        )
    )

    return signed_cert

def save_private_key(private_key, private_key_filename):
    # Save the private key to a file
    with open(private_key_filename, "wb") as private_key_file:
        private_key_bytes = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption()
        )
        private_key_file.write(private_key_bytes)

    # Set the private key file permissions to be readable only by the owner (600)
    os.chmod(private_key_filename, 0o600)

def save_certificate_chain(endpoint_chain_filename, certificate_chain):
    # Save the certificate chain (CA certificates + endpoint certificate)
    with open(endpoint_chain_filename, "wb") as cert_file:
        for cert in certificate_chain:
            cert_file.write(cert.public_bytes(serialization.Encoding.PEM))


# Configure the logging module
logging.basicConfig(format='%(asctime)s - %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.INFO)
logger = logging.getLogger()

def main():
    parser = argparse.ArgumentParser(description="Retrieve certificates using a configuration file.")
    parser.add_argument("--config", default="config.ini", help="Path to the configuration file (INI format)")
    parser.add_argument("--log-file", default="system.log", help="Path to the log file")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                        help="Set the logging level")
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

    # Load configuration from INI file
    config_parser = ConfigParser()
    config_parser.read(args.config)

    # Example usage:
    # Replace 'Your Common Name (CN)' and file paths as needed.

    ca_private_key_filename = "private_root_CA_x509.pem"
    ca_certificate_filename = "certificate_root_CA_x509.pem"
    common_name = "*.test.com"
    endpoint_chain_filename = "chain_node_x509.pem"
    endpoint_private_key_filename = "private_node_x509.pem"

    ca_private_key = serialization.load_pem_private_key(
        open(ca_private_key_filename, "rb").read(),
        password=None,
        backend=default_backend()
    )

    ca_certificate = x509.load_pem_x509_certificate(
        open(ca_certificate_filename, "rb").read(),
        default_backend()
    )

    private_key = generate_private_key()
    csr = create_csr(private_key, common_name)
    signed_certificate = sign_csr_with_ca(csr, ca_private_key, ca_certificate)

    # Save the private key
    save_private_key(private_key, endpoint_private_key_filename)
    
    # Create a list of certificates for the chain (CA certificates + endpoint certificate)
    certificate_chain = [ca_certificate, signed_certificate]

    # Save the certificate chain
    save_certificate_chain(endpoint_chain_filename, certificate_chain)

if __name__ == "__main__":
    main()
