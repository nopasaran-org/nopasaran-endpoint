import socket
import threading
import json
import logging
import os
import sys
import signal
from enum import Enum
from datetime import datetime

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define message types using enumeration for better readability and security
class MessageType(Enum):
    SIGNAL_READY_CONNECTION = "signal_ready_connection"
    SIGNAL_READY_LISTEN = "signal_ready_listen"
    SIGNAL_LISTENING = "signal_listening"
    SIGNAL_READY_STOP = "signal_ready_stop"
    LISTEN = "listen"
    CONNECT = "connect"
    STOP = "stop"
    ERROR = "error"

# Shared state with a timeout and cleanup mechanism
state = {}
lock = threading.Lock()

def handle_client(client_socket, addr):
    global state

    while True:
        try:
            message = client_socket.recv(1024).decode().strip()
            if not message:
                break
            
            data = json.loads(message)
            client_id = data['id']
            command = MessageType(data['type'])

            with lock:
                if client_id not in state:
                    state[client_id] = {
                        'ready_connection': False, 
                        'ready_listen': False, 
                        'listening': False, 
                        'stop_signals': 0,
                        'client_a': None,  # Initiator (Client A)
                        'client_b': None,  # Listener (Client B)
                        'last_updated': datetime.now()
                    }

            logging.info(f"Received {command.value} from {addr} for client_id {client_id}")

            if command == MessageType.SIGNAL_READY_CONNECTION:
                with lock:
                    state[client_id]['ready_connection'] = True
                    state[client_id]['client_a'] = client_socket  # Track Client A
                    state[client_id]['last_updated'] = datetime.now()
                check_for_connection(client_id)

            elif command == MessageType.SIGNAL_READY_LISTEN:
                with lock:
                    state[client_id]['ready_listen'] = True
                    state[client_id]['client_b'] = client_socket  # Track Client B
                    state[client_id]['last_updated'] = datetime.now()
                check_for_connection(client_id)

            elif command == MessageType.SIGNAL_LISTENING:
                with lock:
                    state[client_id]['listening'] = True
                    state[client_id]['last_updated'] = datetime.now()
                # Send an OK response to signal_listening
                client_socket.send(json.dumps({'type': 'OK', 'id': client_id}).encode())
                logging.info(f"Sent OK to Client B for LISTENING confirmation for {client_id}")
                send_connect(client_id)

            elif command == MessageType.SIGNAL_READY_STOP:
                with lock:
                    state[client_id]['stop_signals'] += 1
                    state[client_id]['last_updated'] = datetime.now()
                check_for_stop(client_id)

        except (socket.error, json.JSONDecodeError) as e:
            logging.error(f"Error handling client {addr}: {str(e)}")
            break

def check_for_connection(client_id):
    global state
    with lock:
        if state[client_id]['ready_connection'] and state[client_id]['ready_listen']:
            # Send LISTEN to Client B (listener)
            if state[client_id]['client_b']:
                try:
                    state[client_id]['client_b'].send(json.dumps({'type': MessageType.LISTEN.value, 'id': client_id}).encode())
                    logging.info(f"Sent LISTEN to Client B for {client_id}")
                except:
                    logging.error(f"Failed to send LISTEN to Client B for {client_id}")
            state[client_id]['last_updated'] = datetime.now()

def send_connect(client_id):
    global state
    with lock:
        if state[client_id]['listening'] and state[client_id]['ready_connection']:
            # Send CONNECT to Client A (initiator)
            if state[client_id]['client_a']:
                try:
                    state[client_id]['client_a'].send(json.dumps({'type': MessageType.CONNECT.value, 'id': client_id}).encode())
                    logging.info(f"Sent CONNECT to Client A for {client_id}")
                except:
                    logging.error(f"Failed to send CONNECT to Client A for {client_id}")
            state[client_id]['last_updated'] = datetime.now()

def check_for_stop(client_id):
    global state
    with lock:
        if state[client_id]['stop_signals'] >= 2:
            # Send STOP to both Client A and Client B after receiving both stop signals
            if state[client_id]['client_a']:
                try:
                    state[client_id]['client_a'].send(json.dumps({'type': MessageType.STOP.value, 'id': client_id}).encode())
                    logging.info(f"Sent STOP to Client A for {client_id}")
                except:
                    logging.error(f"Failed to send STOP to Client A for {client_id}")
            if state[client_id]['client_b']:
                try:
                    state[client_id]['client_b'].send(json.dumps({'type': MessageType.STOP.value, 'id': client_id}).encode())
                    logging.info(f"Sent STOP to Client B for {client_id}")
                except:
                    logging.error(f"Failed to send STOP to Client B for {client_id}")
            state[client_id]['stop_signals'] = 0  # Reset for this session
            state[client_id]['last_updated'] = datetime.now()

def daemonize():
    """Daemonizes the process."""
    try:
        # Fork the first time
        pid = os.fork()
        if pid > 0:
            sys.exit(0)  # Exit the parent process

        # Create a new session and set the process group
        if os.setsid() == -1:
            logging.error("Failed to create a new session.")
            sys.exit(1)

        # Fork the second time
        pid = os.fork()
        if pid > 0:
            sys.exit(0)  # Exit the first child process

        # Change the working directory to root
        os.chdir('/')

        # Reset file mode creation mask
        os.umask(0)

        # Redirect standard file descriptors
        with open('/dev/null', 'r') as f:
            os.dup2(f.fileno(), sys.stdin.fileno())
        with open('/dev/null', 'a+') as f:
            os.dup2(f.fileno(), sys.stdout.fileno())
            os.dup2(f.fileno(), sys.stderr.fileno())

        logging.info("Daemon process started successfully.")

    except Exception as e:
        logging.error(f"Error during daemonization: {e}")
        sys.exit(1)

def signal_handler(signum, frame):
    logging.info("Received signal to terminate.")
    sys.exit(0)

def start_server(host='0.0.0.0', port=1963):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)
    logging.info(f"[*] Listening on {host}:{port}")

    while True:
        client_socket, addr = server.accept()
        logging.info(f"Accepted connection from {addr[0]}:{addr[1]}")
        client_handler = threading.Thread(target=handle_client, args=(client_socket, addr))
        client_handler.daemon = True  # Make thread a daemon
        client_handler.start()

if __name__ == "__main__":
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    # Daemonize the process
    daemonize()

    # Start the server
    start_server()
