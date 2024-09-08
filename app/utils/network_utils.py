import socket
import logging

def get_local_ip_for_target(target_ip):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((target_ip, 1))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception as e:
        logging.error(f"Error retrieving local IP: {e}")
        return None

