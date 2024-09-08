import os
import logging
from dotenv import load_dotenv

load_dotenv('/app/resources/config.env', override=False)

required_env_vars = ["ENDPOINT_NAME", "AUTHORIZATION_TOKEN", "ROLE"]

def check_env_vars():
    missing_vars = [var for var in required_env_vars if not os.getenv(var)]
    if missing_vars:
        logging.error(f"Missing environment variables: {', '.join(missing_vars)}")
        exit(1)

check_env_vars()

def get_env_variable(name):
    return os.getenv(name)
