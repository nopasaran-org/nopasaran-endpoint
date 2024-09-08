import os
import logging
from iptables.iptables_helper import remove_rule_by_name


# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define the file where rule names were stored
rule_names_file = "./iptables_rule_names.txt"

# Get the chain name from the environment variable
chain_name = os.environ.get('OUTPUT_CHAIN')

# Read the rule names and remove them
if os.path.exists(rule_names_file):
    with open(rule_names_file, 'r') as f:
        rule_names = f.readlines()
    
    for rule_name in rule_names:
        rule_name = rule_name.strip()
        remove_rule_by_name(chain_name, rule_name)
    
    # Optionally, remove the file after processing
    os.remove(rule_names_file)
else:
    logging.warning(f"No rule names file found at {rule_names_file}.")
