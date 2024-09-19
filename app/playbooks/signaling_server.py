import socket
import threading
import time
import json
import logging
import os
import sys
import signal
from enum import Enum
from datetime import datetime, timedelta
import fcntl

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', 
                    filename="/var/log/signaling_server.log",
                    filemode="a")

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

# Directory to store state files
STATE_DIR = "/var/run/signaling_server_states/"
CLEANUP_INTERVAL = 60  # Time to clean up old connections in seconds

def ensure_state_dir():
    """Ensure the state directory exists."""
    os.makedirs(STATE_DIR, exist_ok=True)

def get_state_file_path(client_id):
    """Get the file path for a client's state file."""
    return os.path.join(STATE_DIR, f"{client_id}.json")

def load_state(client_id):
    """Load state from file for a specific client."""
    file_path = get_state_file_path(client_id)
    try:
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                fcntl.flock(f, fcntl.LOCK_SH)
                state = json.load(f)
                fcntl.flock(f, fcntl.LOCK_UN)
            return state
        return None
    except Exception as e:
        logging.error(f"Error loading state for client {client_id}: {e}")
        return None

def save_state(client_id, state):
    """Save state to file for a specific client."""
    file_path = get_state_file_path(client_id)
    try:
        with open(file_path, 'w') as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            json.dump(state, f)
            fcntl.flock(f, fcntl.LOCK_UN)
    except Exception as e:
        logging.error(f"Error saving state for client {client_id}: {e}")

def clean_state():
    """Cleans up client states that have not been active for CLEANUP_INTERVAL seconds."""
    while True:
        time.sleep(10)  # Run cleanup every 10 seconds
        try:
            now = datetime.now()
            for filename in os.listdir(STATE_DIR):
                file_path = os.path.join(STATE_DIR, filename)
                if os.path.isfile(file_path):
                    mod_time = datetime.fromtimestamp(os.path.getmtime(file_path))
                    if now - mod_time > timedelta(seconds=CLEANUP_INTERVAL):
                        os.remove(file_path)
                        logging.info(f"Cleaned up state file for {filename}")
        except Exception as e:
            logging.error(f"Error during state cleanup: {e}")

def handle_client(client_socket, addr):
    while True:
        try:
            message = client_socket.recv(1024).decode().strip()
            if not message:
                break
            
            data = json.loads(message)
            client_id = data['id']
            command = MessageType(data['type'])

            state = load_state(client_id)
            if state is None:
                state = {
                    'ready_connection': False, 
                    'ready_listen': False, 
                    'listening': False,  # Initialize listening as False
                    'stop_signals': 0,
                    'last_updated': datetime.now().isoformat()
                }
            
            logging.info(f"Received {command.value} from {addr} for client_id {client_id}")

            if command == MessageType.SIGNAL_READY_CONNECTION:
                state['ready_connection'] = True
                state['last_updated'] = datetime.now().isoformat()
                save_state(client_id, state)
                # Wait until listening is True before sending connect
                wait_for_listening(client_id, client_socket)

            elif command == MessageType.SIGNAL_READY_LISTEN:
                state['ready_listen'] = True
                state['last_updated'] = datetime.now().isoformat()
                save_state(client_id, state)
                wait_for_connection(client_id, client_socket)

            elif command == MessageType.SIGNAL_LISTENING:
                state['listening'] = True  # Set listening to True
                state['last_updated'] = datetime.now().isoformat()
                save_state(client_id, state)
                client_socket.send(json.dumps({'type': 'OK', 'id': client_id}).encode())
                logging.info(f"Sent OK to Client B for LISTENING confirmation for {client_id}")

            elif command == MessageType.SIGNAL_READY_STOP:
                state['stop_signals'] += 1
                state['last_updated'] = datetime.now().isoformat()
                save_state(client_id, state)
                wait_for_stop(client_id, client_socket)

        except (socket.error, json.JSONDecodeError) as e:
            logging.error(f"Error handling client {addr}: {str(e)}")
            break

    client_socket.close()

def wait_for_listening(client_id, client_socket, timeout=10):
    """Wait until listening is True before sending connect."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        state = load_state(client_id)
        if state and state['listening']:
            send_connect(client_id, client_socket)
            return
        time.sleep(0.1)

    logging.error(f"Timeout waiting for listening for client {client_id}")

def wait_for_connection(client_id, client_socket, timeout=10):
    """Check if both ready_connection and ready_listen are True, with a timeout."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        state = load_state(client_id)
        if state and state['ready_connection'] and state['ready_listen']:
            try:
                client_socket.send(json.dumps({'type': MessageType.LISTEN.value, 'id': client_id}).encode())
                logging.info(f"Sent LISTEN for {client_id}")
            except Exception as e:
                logging.error(f"Failed to send LISTEN for {client_id}: {e}")
            state['last_updated'] = datetime.now().isoformat()
            save_state(client_id, state)
            return
        time.sleep(0.1)

    logging.error(f"Timeout waiting for connection readiness for client {client_id}")

def send_connect(client_id, client_socket):
    state = load_state(client_id)
    if state and state['listening'] and state['ready_connection']:
        try:
            client_socket.send(json.dumps({'type': MessageType.CONNECT.value, 'id': client_id}).encode())
            logging.info(f"Sent CONNECT for {client_id}")
        except Exception as e:
            logging.error(f"Failed to send CONNECT for {client_id}: {e}")
        state['last_updated'] = datetime.now().isoformat()
        save_state(client_id, state)

def wait_for_stop(client_id, client_socket, timeout=10):
    """Check if both stop signals have been received, with a timeout."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        state = load_state(client_id)
        if state and state['stop_signals'] >= 2:
            try:
                client_socket.send(json.dumps({'type': MessageType.STOP.value, 'id': client_id}).encode())
                logging.info(f"Sent STOP for {client_id}")
            except Exception as e:
                logging.error(f"Failed to send STOP for {client_id}: {e}")
            state['last_updated'] = datetime.now().isoformat()
            save_state(client_id, state)
            return
        time.sleep(0.1)

    logging.error(f"Timeout waiting for stop signals for client {client_id}")


def daemonize():
    """Daemonizes the process."""
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
        os.setsid()
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
        os.chdir('/')
        os.umask(0)
        
        # Redirect standard file descriptors to /dev/null
        with open(os.devnull, 'r') as nullin, open(os.devnull, 'w') as nullout, open(os.devnull, 'w') as nullerr:
            os.dup2(nullin.fileno(), sys.stdin.fileno())
            os.dup2(nullout.fileno(), sys.stdout.fileno())
            os.dup2(nullerr.fileno(), sys.stderr.fileno())
        
        logging.info("Daemon process started successfully.")
    except Exception as e:
        logging.error(f"Error during daemonization: {e}")
        sys.exit(1)

def signal_handler(signum, frame):
    logging.info("Received signal to terminate.")
    sys.exit(0)

def start_server(host='0.0.0.0', port=1963):
    ensure_state_dir()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(128)
    logging.info(f"[*] Listening on {host}:{port}")

    cleanup_thread = threading.Thread(target=clean_state)
    cleanup_thread.daemon = True
    cleanup_thread.start()

    while True:
        try:
            client_socket, addr = server.accept()
            logging.info(f"Accepted connection from {addr[0]}:{addr[1]}")
            client_handler = threading.Thread(target=handle_client, args=(client_socket, addr))
            client_handler.daemon = True
            client_handler.start()
        except Exception as e:
            logging.error(f"Error accepting connection: {e}")

if __name__ == "__main__":
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    daemonize()
    start_server()