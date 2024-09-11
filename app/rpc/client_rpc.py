import base64
import pickle
import asyncio
from fastapi_websocket_rpc.rpc_methods import RpcUtilityMethods
from services.netbird_service import restart_daemons
from tasks_publisher import publish_task

from certificates.certificate_manager import CertificateManager
from certificates.certificate_validator import CertificateValidator

class ClientRPC(RpcUtilityMethods):
    def __init__(self):
        super().__init__()
        self.can_exit = asyncio.Event()

    @staticmethod
    def encode(data):
        serialized = pickle.dumps(data)
        return base64.b64encode(serialized).decode('utf-8')

    @staticmethod
    def decode(encoded_data):
        decoded = base64.b64decode(encoded_data)
        return pickle.loads(decoded)

    @staticmethod
    def generate_certificates(hostname):
        validator = CertificateValidator()
        if False in validator.check_certificate_files():
            cert_manager = CertificateManager(hostname)
            cert_manager.retrieve_certificate()
            return True
        return False
    
    async def restart(self):
        restart_daemons()

    async def allow_exit(self):
        self.can_exit.set()

    async def execute_task(self, task_id="", repository="", tests_tree="", nodes="", variables=""):
        try:
            publish_task(task_id, repository, tests_tree, nodes, variables)
            return "+ Submitted"
        except Exception as e:
            return f"- {str(e)}"
