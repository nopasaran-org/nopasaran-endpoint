import dotenv

import sys
import os 
import json
import logging

# Absolute path to the directory containing the app
app_path = "/app"

# Add the directory to sys.path
sys.path.append(app_path)

from iptables.iptables_helper import add_tcp_drop_rule_to_chain_and_get_name

# Load the .env file, but don't override existing environment variables
dotenv.load_dotenv('/app/resources/config.env', override=False)

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define a file to store rule names
rule_names_file = "./iptables_rule_names.txt"

# Get the filename from the command line arguments
filename = sys.argv[1]

# Open and read the file
with open(filename, 'r') as file:
    # Read the file content
    data = file.read()

# Parse the JSON string into a dictionary
dict = json.loads(data)
required_data = dict.get("required")

chain_name = os.environ.get('OUTPUT_CHAIN')

# Open the file to store rule names
with open(rule_names_file, 'w') as f:
    for rule in required_data.get("iptables", []):
        protocol = rule.get("protocol")
        sport = rule.get("sport")
        dport = rule.get("dport")
        tcp_flags = rule.get("tcp_flags")
        
        if protocol == "tcp":
            rule_name = add_tcp_drop_rule_to_chain_and_get_name(chain_name, sport, dport, tcp_flags)
            # Save the rule name to the file
            f.write(rule_name + '\n')
        else:
            logging.warning(f"Unsupported protocol: {protocol}")
