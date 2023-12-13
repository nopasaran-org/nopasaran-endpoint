import re
import psutil
import time

# Define the output file path
output_file = "/ansible/inventory.ini"

def extract_connections(auth_log_path):
    accepted_publickey_pattern = re.compile(r'Accepted publickey for (\w+) from ([\d.]+) port \d+ ssh2: RSA-CERT .+ ID (\S+)')
    connections = {}

    with open(auth_log_path, 'r') as log_file:
        for line in log_file:
            match_accepted_publickey = accepted_publickey_pattern.search(line)

            if match_accepted_publickey:
                username = match_accepted_publickey.group(1)
                ip_address = match_accepted_publickey.group(2)
                hostname = match_accepted_publickey.group(3)
                pid = re.search(r'sshd\[(\d+)\]', line).group(1)

                connections[pid] = {'hostname': hostname}

    return connections

def filter_running_connections(connections):
    running_connections = {}

    for pid in connections:
        try:
            process = psutil.Process(int(pid))
            if process.is_running():
                running_connections[pid] = connections[pid]
        except psutil.NoSuchProcess:
            pass  # Process no longer exists

    return running_connections

def get_child_processes_for_connection(connections, pid):
    child_processes = []
    if pid in connections:
        try:
            parent_process = psutil.Process(int(pid))
            for child in parent_process.children(recursive=True):
                child_processes.append({'pid': child.pid, 'name': child.name()})
        except psutil.NoSuchProcess:
            pass  # Parent process no longer exists

    return child_processes

def get_listening_port_for_process(pid):
    listening_port = None
    try:
        process = psutil.Process(pid)
        connections = process.connections(kind='inet')
        for conn in connections:
            if conn.status == psutil.CONN_LISTEN:
                listening_port = conn.laddr.port
                break
    except psutil.NoSuchProcess:
        pass

    return listening_port

def write_host_file(host_port_list):
    # Write the (hostname, port) pairs to the output file in the desired format
    with open(output_file, 'w') as file:
        file.write("[nopasaran_nodes]\n")
        for hostname, port in host_port_list:
            file.write(f"{hostname} ansible_port={port} ansible_user=manager\n")

def main():
    auth_log_path = '/var/log/auth.log'

    while True:
        connections = extract_connections(auth_log_path)
        running_connections = filter_running_connections(connections)
        
        # Create a list of (hostname, port) pairs
        host_port_list = []

        # Extract the hostname and port of running connections
        if running_connections:
            for pid, data in running_connections.items():
                hostname = data['hostname']
                
                # Get child processes for the current running connection
                child_processes = get_child_processes_for_connection(running_connections, pid)
                if child_processes:
                    for child in child_processes:
                        # Get and print listening port for the child process
                        listening_port = get_listening_port_for_process(child['pid'])
                        if listening_port:
                            host_port_list.append((hostname, 1963))
        
        write_host_file(host_port_list)
        
        # Sleep for 1 second before checking again
        time.sleep(1)

if __name__ == "__main__":
    main()