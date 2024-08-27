import os
import dotenv

def get_certificates_list():
    # Load the .env file, but don't override existing environment variables
    dotenv.load_dotenv('/app/resources/config.env', override=False)

    # Retrieve values of environment variables
    USER_OUTPUT_PATH = os.path.expanduser(os.getenv("USER_OUTPUT_PATH"))
    USER_OUTPUT_FILENAME = os.getenv("USER_OUTPUT_FILENAME")
    HOST_OUTPUT_PATH = os.getenv("HOST_OUTPUT_PATH")
    HOST_OUTPUT_FILENAME = os.getenv("HOST_OUTPUT_FILENAME")
    OTHER_CA_OUTPUT_PATH = os.path.expanduser(os.getenv("OTHER_CA_OUTPUT_PATH"))
    OTHER_CA_OUTPUT_FILENAME = os.getenv("OTHER_CA_OUTPUT_FILENAME")
    OWN_CA_OUTPUT_PATH = os.path.expanduser(os.getenv("OWN_CA_OUTPUT_PATH"))
    OWN_CA_OUTPUT_FILENAME = os.getenv("OWN_CA_OUTPUT_FILENAME")
    X509_PATH = os.getenv("X509_PATH")
    X509_FILENAME_CA = os.getenv("X509_FILENAME_CA")
    X509_FILENAME_PRIVATE_CRT = os.getenv("X509_FILENAME_PRIVATE_CRT")

    # Check if the files exist and return their contents or False if they don't exist
    certificate_contents = {
        "user_cert_path": os.path.join(USER_OUTPUT_PATH, USER_OUTPUT_FILENAME) if USER_OUTPUT_PATH and USER_OUTPUT_FILENAME else None,
        "host_cert_path": os.path.join(HOST_OUTPUT_PATH, HOST_OUTPUT_FILENAME) if HOST_OUTPUT_PATH and HOST_OUTPUT_FILENAME else None,
        "other_ca_cert_path": os.path.join(OTHER_CA_OUTPUT_PATH, OTHER_CA_OUTPUT_FILENAME) if OTHER_CA_OUTPUT_PATH and OTHER_CA_OUTPUT_FILENAME else None,
        "own_ca_cert_path": os.path.join(OWN_CA_OUTPUT_PATH, OWN_CA_OUTPUT_FILENAME) if OWN_CA_OUTPUT_PATH and OWN_CA_OUTPUT_FILENAME else None,
        "x509_ca_certificate_path": os.path.join(X509_PATH, X509_FILENAME_CA) if X509_PATH and X509_FILENAME_CA else None,
        "x509_private_certificate_path": os.path.join(X509_PATH, X509_FILENAME_PRIVATE_CRT) if X509_PATH and X509_FILENAME_PRIVATE_CRT else None,
    }

    certificates = []
    for _, cert_path in certificate_contents.items():
        if cert_path:
            if os.path.isfile(cert_path):
                certificates.append(True)
            else:
                certificates.append(False)
        else:
            certificates.append(False)
    return certificates
