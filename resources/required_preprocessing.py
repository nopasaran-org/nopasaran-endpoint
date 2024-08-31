import dotenv

import sys
import os 
import json
import logging
from iptables_rules import add_tcp_drop_rule_to_chain_and_get_name

# Load the .env file, but don't override existing environment variables
dotenv.load_dotenv('/app/resources/config.env', override=False)

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define a file to store rule names
rule_names_file = "./iptables_rule_names.txt"

# Get the dictionary (as a JSON string) passed from a bash script
required_dict_str = sys.argv[1]

# Parse the JSON string into a dictionary
data = json.loads(required_dict_str)

chain_name = os.environ.get('OUTPUT_CHAIN')

# Open the file to store rule names
with open(rule_names_file, 'w') as f:
    for rule in data.get("iptables", []):
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
