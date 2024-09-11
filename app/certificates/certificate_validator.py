import os
import logging
import dotenv
from datetime import datetime, timezone

from certificates.file_handler import FileHandler

# Load the .env file, but don't override existing environment variables
dotenv.load_dotenv('/app/resources/config.env', override=False)

# Set up logging
logging.basicConfig(format='%(asctime)s - %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.INFO)

class CertificateValidator:
    """Class to validate the existence and expiration of necessary certificates."""

    def __init__(self):
        self.x509_path = os.getenv("X509_PATH")
        self.ca_cert_file = os.getenv("X509_FILENAME_CA")
        self.private_cert_file = os.getenv("X509_FILENAME_PRIVATE_CRT")

    def check_certificate_files(self):
        """Check the validity of the certificates both in terms of existence and expiration date."""
        paths = {
            "ca_cert": os.path.join(self.x509_path, self.ca_cert_file) if self.ca_cert_file else None,
            "private_cert": os.path.join(self.x509_path, self.private_cert_file) if self.private_cert_file else None
        }

        certificate_status = []
        for _, path in paths.items():
            if path and os.path.isfile(path):
                cert = FileHandler.load_certificate(path)
                if cert:
                    is_valid_in_time = self._is_certificate_valid_in_time(cert)
                    certificate_status.append(is_valid_in_time)
                else:
                    certificate_status.append(False)
            else:
                certificate_status.append(False)

        return certificate_status

    def _is_certificate_valid_in_time(self, certificate):
        """Check if the certificate is valid within its validity period."""
        current_time = datetime.now(timezone.utc)
        not_valid_before = certificate.not_valid_before_utc
        not_valid_after = certificate.not_valid_after_utc

        if not_valid_before <= current_time <= not_valid_after:
            logging.info(f"Certificate is valid (not valid before: {not_valid_before}, not valid after: {not_valid_after}).")
            return True
        else:
            logging.warning(f"Certificate is expired or not yet valid (valid from {not_valid_before} to {not_valid_after}).")
            return False
