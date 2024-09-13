import subprocess
import logging
import re

def restart_daemons():
    try:
        logging.info("Restarting Netbird daemons...")
        subprocess.run(["netbird", "service", "start"], check=True)
        exit(0)
        logging.info("Daemons restarted successfully.")
    except Exception as e:
        logging.error(f"Error restarting daemons: {e}")


def get_netbird_ip():
    try:
        result = subprocess.run(['netbird', 'status'], capture_output=True, text=True, check=True)
        match = re.search(r'NetBird IP: (\d+\.\d+\.\d+\.\d+)', result.stdout)
        return match.group(1) if match else None
    except subprocess.CalledProcessError:
        logging.error("Failed to get Netbird IP.")
        return None

def configure_netbird_key(setup_key, hostname):
    try:
        # Start the subprocess and capture its output in real-time
        process = subprocess.Popen(
            ["netbird", "up", "--setup-key", setup_key, "--hostname", hostname],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # Process the output line by line
        for stdout_line in iter(process.stdout.readline, ''):
            logging.info(stdout_line.strip())
            if "setup key is invalid" in stdout_line:
                logging.error("Setup key is invalid. Terminating the process.")
                process.terminate()  # Terminate the process early
                break

        # Ensure that the process finishes after termination or completion
        process.communicate()

        if process.returncode != 0:
            raise subprocess.CalledProcessError(process.returncode, process.args)
        
        logging.info("Netbird configured successfully.")

    except subprocess.CalledProcessError as e:
        logging.error(f"Error configuring Netbird: {e}")
