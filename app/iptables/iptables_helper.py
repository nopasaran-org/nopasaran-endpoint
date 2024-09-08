import os
import uuid
import iptc
import logging
import dotenv

# Load the .env file, but don't override existing environment variables
dotenv.load_dotenv('/app/resources/config.env', override=False)

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def chain_exists(chain_name):
    """Check if a chain exists in the filter table."""
    table = iptc.Table(iptc.Table.FILTER)
    return any(chain.name == chain_name for chain in table.chains)

def create_chain(chain_name):
    """Create a custom chain in the filter table if it does not already exist."""
    table = iptc.Table(iptc.Table.FILTER)
    
    if not chain_exists(chain_name):
        table.create_chain(chain_name)
        logging.info(f"Chain {chain_name} created.")
    else:
        logging.info(f"Chain {chain_name} already exists.")
    
    return iptc.Chain(table, chain_name)

def add_reference_rule_to_output_chain(custom_chain_name):
    """Add a reference rule to the OUTPUT chain to direct traffic to the custom chain."""
    output_chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), 'OUTPUT')

    # Create a rule to jump to the custom chain
    rule = iptc.Rule()
    rule.target = iptc.Target(rule, custom_chain_name)

    # Check if the reference rule already exists
    for existing_rule in output_chain.rules:
        if existing_rule.target.name == custom_chain_name:
            logging.info(f"Reference to {custom_chain_name} already exists in OUTPUT chain.")
            return

    # Insert the reference rule at the beginning of the OUTPUT chain
    output_chain.insert_rule(rule)
    logging.info(f"Reference rule to {custom_chain_name} added to OUTPUT chain.")

def add_tcp_drop_rule_to_chain_and_get_name(chain_name, sport=None, dport=None, tcp_flags=None):
    """Add a custom TCP DROP rule with a random name to the specified chain and return the name of the newly added rule."""
    # Generate a random name for the rule
    rule_name = str(uuid.uuid4())
    
    # Get the chain by name
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), chain_name)
    
    # Create a new rule
    rule = iptc.Rule()
    rule.protocol = 'tcp'
    
    # Add match conditions
    match = rule.create_match("tcp")
    if sport:
        match.sport = sport
    if dport:
        match.dport = dport
    if tcp_flags:
        match.tcp_flags = tcp_flags
    
    # Add a comment match with the rule name
    comment = rule.create_match("comment")
    comment.comment = rule_name
    
    # Set the target to DROP
    rule.target = iptc.Target(rule, 'DROP')
    
    # Append the rule at the end of the chain
    chain.append_rule(rule)
    logging.info(f"Rule appended to {chain_name}: SPORT={sport}, DPORT={dport}, TCP_FLAGS={tcp_flags}, NAME={rule_name}")
    
    # Return the name of the newly added rule
    return rule_name

def list_rules_in_chain(chain_name):
    """List all rules in the specified chain."""
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), chain_name)
    rules = []
    for index, rule in enumerate(chain.rules):
        rule_str = str(rule)
        rules.append((index, rule_str))
        logging.info(f"Rule {index}: {rule_str}")
    return rules

def remove_rule_by_name(chain_name, rule_name):
    """Remove a rule from the specified chain by its comment (name)."""
    # Get the chain by name
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), chain_name)
    
    # Iterate through the rules in the chain
    for rule in chain.rules:
        for match in rule.matches:
            if match.name == "comment" and match.comment == rule_name:
                chain.delete_rule(rule)
                logging.info(f"Rule with name '{rule_name}' removed from {chain_name}.")
                return True
    
    logging.warning(f"No rule with name '{rule_name}' found in {chain_name}.")
    return False

def remove_rule_by_index(chain_name, index):
    """Remove a rule from the specified chain based on its index."""
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), chain_name)
    rules = list_rules_in_chain(chain_name)
    
    if index < 0 or index >= len(rules):
        logging.error(f"Invalid index {index}. No rule at this index.")
        return
    
    rule_to_remove = chain.rules[index]
    chain.delete_rule(rule_to_remove)
    logging.info(f"Rule at index {index} removed from {chain_name}.")

def remove_reference_rule_from_output_chain(custom_chain_name):
    """Remove the reference rule from the OUTPUT chain."""
    output_chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), 'OUTPUT')

    # Iterate through the rules and remove the one that references the custom chain
    for rule in output_chain.rules:
        if rule.target.name == custom_chain_name:
            output_chain.delete_rule(rule)
            logging.info(f"Reference rule to {custom_chain_name} removed from OUTPUT chain.")
            return

    logging.info(f"No reference rule to {custom_chain_name} found in OUTPUT chain.")

def delete_chain(chain_name):
    """Delete the specified chain after ensuring it's not referenced."""
    table = iptc.Table(iptc.Table.FILTER)
    
    # Ensure the chain is not referenced in the OUTPUT chain
    remove_reference_rule_from_output_chain(chain_name)
    
    # Refresh the table to sync with current iptables state
    table.refresh()

    if chain_exists(chain_name):
        chain = iptc.Chain(table, chain_name)
        chain.flush()  # Clear all rules in the chain
        table.delete_chain(chain_name)
        logging.info(f"Chain {chain_name} deleted.")
    else:
        logging.info(f"Chain {chain_name} does not exist.")
        
        
def init():
    chain_name = os.environ.get('OUTPUT_CHAIN')
    create_chain(chain_name)
    add_reference_rule_to_output_chain(chain_name)
    
init()