import os
import logging

import dotenv
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_certificate(cert_path):
    """Helper function to load a certificate from a file."""
    try:
        with open(cert_path, 'rb') as cert_file:
            cert_data = cert_file.read()
            certificate = x509.load_pem_x509_certificate(cert_data, default_backend())
            return certificate
    except Exception as e:
        logging.error(f"Error loading certificate {cert_path}: {e}")
        return None

def get_certificates_list():
    # Load the .env file, but don't override existing environment variables
    dotenv.load_dotenv('/app/resources/config.env', override=False)

    # Retrieve values of environment variables
    X509_PATH = os.getenv("X509_PATH")
    X509_FILENAME_CA = os.getenv("X509_FILENAME_CA")
    X509_FILENAME_PRIVATE_CRT = os.getenv("X509_FILENAME_PRIVATE_CRT")

    # Check if the files exist and return their contents or False if they don't exist
    certificate_contents = {
        "x509_ca_certificate_path": os.path.join(X509_PATH, X509_FILENAME_CA) if X509_PATH and X509_FILENAME_CA else None,
        "x509_private_certificate_path": os.path.join(X509_PATH, X509_FILENAME_PRIVATE_CRT) if X509_PATH and X509_FILENAME_PRIVATE_CRT else None,
    }

    certificates = []
    for key, cert_path in certificate_contents.items():
        if cert_path and os.path.isfile(cert_path):
            if "x509" in key:
                # Load and validate the certificate (for x509 paths)
                cert = load_certificate(cert_path)
                if cert:
                    certificates.append(True)
                else:
                    certificates.append(False)
            else:
                # Just check if the file exists for non-x509 paths
                certificates.append(True)
        else:
            certificates.append(False)

    return certificates
