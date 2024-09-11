import os
import logging
import dotenv
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Load the .env file, but don't override existing environment variables
dotenv.load_dotenv('/app/resources/config.env', override=False)

# Set up logging
logging.basicConfig(format='%(asctime)s - %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.INFO)

class FileHandler:
    """Class to handle file read and write operations."""

    @staticmethod
    def save_to_file(content, output_path, output_filename):
        if not output_path:
            output_path = os.getcwd()
        expanded_output_path = os.path.expanduser(output_path)
        output_file_path = os.path.join(expanded_output_path, output_filename)
        os.makedirs(os.path.dirname(output_file_path), exist_ok=True)
        with open(output_file_path, "wb") as file:
            file.write(content)
        logging.info(f"File saved to {output_file_path}")

    @staticmethod
    def load_certificate(cert_path):
        try:
            with open(cert_path, 'rb') as cert_file:
                cert_data = cert_file.read()
                certificate = x509.load_pem_x509_certificate(cert_data, default_backend())
                return certificate
        except Exception as e:
            logging.error(f"Error loading certificate {cert_path}: {e}")
            return None