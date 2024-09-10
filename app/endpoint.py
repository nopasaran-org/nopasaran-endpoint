import asyncio
import logging
import subprocess
from services.netbird_service import restart_daemons, configure_netbird_key, get_netbird_ip
from services.task_service import periodic_result_reader
from rpc.client_rpc import ClientRPC
from fastapi_websocket_rpc import WebSocketRpcClient, logger
from config import get_env_variable
from utils.network_utils import get_local_ip_for_target

logger.logging_config.set_mode(logger.LoggingModes.UVICORN, logger.logging.DEBUG)
logging.basicConfig(level=logging.INFO)


host = get_env_variable('SERVER_HOST')
port = int(get_env_variable('SERVER_PORT'))
auth_token = get_env_variable('AUTHORIZATION_TOKEN')
endpoint_name = get_env_variable('ENDPOINT_NAME')
role = get_env_variable('ROLE')

async def on_connect(channel):
    # Generate certificates and configure the connection
    need_restart = ClientRPC.generate_certificates()

    hostname_response = await channel.other.get_hostname()
    hostname = ClientRPC.decode(hostname_response.result)

    endpoint_response = await channel.other.get_endpoint()
    endpoint = ClientRPC.decode(endpoint_response.result)

    configure_netbird_key(endpoint['mesh_key_setup'], hostname)

    netbird_ip = get_netbird_ip()
    client_private_ip = get_local_ip_for_target(host)
    
    if netbird_ip is None:
        setup_key_response = await asyncio.create_task(channel.other.update_setup_key()) 
        setup_key = ClientRPC.decode(setup_key_response.result)
        if setup_key:
            configure_netbird_key(setup_key, hostname)

    if netbird_ip is None or need_restart:
        restart_daemons()

    ips = ClientRPC.encode({
        "netbird_ip": netbird_ip,
        "client_private_ip": client_private_ip
    })

    await channel.other.set_ips(ips=ips)


async def run_client(uri):
    if role == "worker":
        try:
            # Execute the worker process
            result = subprocess.run(["python", "/app/playbooks/worker.py"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            logging.info(f"Worker process executed successfully: {result.stdout}")
        except subprocess.CalledProcessError as e:
            logging.error(f"Worker process failed: {e.stderr}")
    while True:
        try:
            async with WebSocketRpcClient(uri, ClientRPC(), on_connect=[on_connect]) as client:
                result_reader_task = asyncio.create_task(periodic_result_reader(client.channel))
                task1 = asyncio.create_task(client.channel.methods.can_exit.wait())
                task2 = asyncio.create_task(client.channel._closed.wait())
                await asyncio.wait(
                    [task1, task2],
                    return_when=asyncio.FIRST_COMPLETED
                )
                result_reader_task.cancel()            
        except Exception as e:
            logging.error(f"Error: {e}")
            await asyncio.sleep(3)


def main():
    # Prepare WebSocket URI with query params
    scheme = "wss" if port == 443 else "ws"
    uri = f"{scheme}://{host}:{port}/ws/endpoints?token={auth_token}&endpoint_name={endpoint_name}"

    asyncio.run(run_client(uri))


if __name__ == "__main__":
    main()
