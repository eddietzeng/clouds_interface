import logging

from azure.identity import ClientSecretCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient

from .base import AbstractCloud

logging.getLogger('azure.core.pipeline.policies.http_logging_policy').setLevel(logging.WARNING)
logger = logging.getLogger(__name__)


class Azure(AbstractCloud):
    def __init__(self, sub_id, tenant_id, client_id, client_secret):
        super(Azure, self).__init__()
        self.subscription_id = sub_id
        self.credentials = self.get_ad_sp_credential(
            tenant_id,
            client_id,
            client_secret
        )
        if not self._check_cred_id():
            raise RuntimeError("Please check Azure RM credential.")
        self._compute_client = None
        self._network_client = None

    def get_ad_sp_credential(self, tenant_id, client_id, client_secret):
        """Initialize Azure credentials by ServicePrincipalCredentials()

        :param tenant_id(str): Azure tenant id
        :param client_id(str): Azure client id
        :param client_secret(str): Azure client secret

        :return: credentials or None
        """
        try:
            credentials = ClientSecretCredential(
                client_id=client_id,
                client_secret=client_secret,
                tenant_id=tenant_id
            )
            logger.info('get_ad_sp_credential successful.')
            return credentials
        except Exception as e:
            logger.error(e, exc_info=True)
            return None

    @classmethod
    def from_credential(cls, cred):
        """Return cloud object

        :param cls
        :param cred: credential retrieved by retrieve_secret()

        :return: object

        For example:
            secret_name = "copilot/smoke_test/aws/xxxxx"
            cred = retrieve_secret(secret_name)[secret_name]
        """
        sub_id = cred["subscription_id"]
        tenant_id = cred["tenant_id"]
        client_id = cred["client_id"]
        client_secret = cred["client_secret"]
        return cls(sub_id, tenant_id, client_id, client_secret)

    @property
    def compute_client(self):
        if self._compute_client is None:
            self._compute_client = ComputeManagementClient(
                self.credentials, self.subscription_id)
        return self._compute_client

    @property
    def network_client(self):
        if self._network_client is None:
            self._network_client = NetworkManagementClient(
                self.credentials, self.subscription_id)
        return self._network_client

    def start_instance(self, vm_name, group_name, **kwargs):
        """Start Azure instance

        :param vm_name: vm name to be starting
        :param group_name: group name of instance to be starting
        """
        logger.info("Start Azure Instance: %s" % vm_name)
        vm_start = self.compute_client.virtual_machines.begin_start(
            group_name, vm_name)
        vm_start.wait()

    def stop_instance(self, vm_name, group_name, **kwargs):
        """Stop Azure instance

        :param vm_name: vm name to be stopping
        :param group_name: group name of instance to be stopping
        """
        logger.info("Stop Azure Instance: %s" % vm_name)
        vm_stop = self.compute_client.virtual_machines.begin_deallocate(group_name,
                                                                        vm_name)
        vm_stop.wait()

    def get_instance_ip(self, vm_name, group_name):
        """Get public ip and private ip from Azure instance

        :param vm_name: vm name to be starting
        :param group_name: group name of instance to be starting

        :return:
            public_ip(str)
            private_ip(str)
        """
        pub_ip, pri_ip = "", ""
        instances = self.compute_client.virtual_machines.list(group_name)
        for instance in instances:
            if instance.name == vm_name:
                reference = instance.network_profile.network_interfaces[0]
                reference = reference.id.split("/")
                i_group = reference[4]
                i_name = reference[8]

        net_interface = self.network_client.network_interfaces.get(
            i_group,
            i_name
        )
        pri_ip = net_interface.ip_configurations[0].private_ip_address
        try:
            ip_reference = net_interface.ip_configurations[0].public_ip_address
            ip_reference = ip_reference.id.split('/')
            ip_group = ip_reference[4]
            ip_name = ip_reference[8]

            public_ip = self.network_client.public_ip_addresses.get(
                ip_group, ip_name)
            pub_ip = public_ip.ip_address
        except AttributeError:
            logger.error("Failed to set public ip, the vm may have private ip only", exc_info=True)
        except Exception:
            logger.error("Failed to get instance ip", exc_info=True)
        return pub_ip, pri_ip

    def _check_cred_id(self):
        """Verify Azure credentials 

        :return: True or False
        """
        if self.credentials is None or self.subscription_id == '':
            reason = 'Azure RM credential not available. Please check Azure RM credential.'
            logger.error(reason, exc_info=True)
            return False
        else:
            return True
