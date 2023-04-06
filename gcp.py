import os
import json
import time
import logging

from googleapiclient import discovery
from google.oauth2 import service_account

from .base import AbstractCloud

logger = logging.getLogger(__name__)


class GCP(AbstractCloud):
    def __init__(self, project_id, cred_content):
        super(GCP, self).__init__()
        self.project_id = project_id
        info = json.loads(cred_content)
        credentials = service_account.Credentials.from_service_account_info(
            info)
        self.compute = discovery.build(
            'compute',
            'v1',
            credentials=credentials
        )

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
        project_id, cred_content = cred["project_id"], cred["credential"]
        return cls(project_id, cred_content)

    def start_instance(self, instance_id, zone, **kwargs):
        """Start GCP instance

        :param instance_id: instance id to be starting
        :param zone: zone where instance is located
        """
        # TODO: make another way to start instance more efficient
        try:
            logger.info("Start GCP Instance: %s" % instance_id)
            self.compute.instances().start(
                project=self.project_id,
                zone=zone,
                instance=instance_id
            ).execute()
            while True:
                time.sleep(15)
                status = self.get_instance_info(
                    instance_id,
                    zone,
                    keyword="status"
                )
                if status == "RUNNING":
                    break
        except Exception as e:
            logger.error("Failed to start gcp instance", exc_info=True)
            raise RuntimeError(e)

    def stop_instance(self, instance_id, zone, **kwargs):
        """Stop GCP instance

        :param instance_id: instance id to be stopping
        :param zone: zone where instance is located
        """
        # TODO: make another way to stop instance more efficient
        try:
            logger.info("Stop GCP Instance: %s" % instance_id)
            self.compute.instances().stop(
                project=self.project_id,
                zone=zone,
                instance=instance_id
            ).execute()
        except Exception as e:
            logger.error("Failed to stop gcp instance", exc_info=True)
            raise RuntimeError(e)

    def get_instance_info(self, instance_id, zone, **kwargs):
        """Get GCP instance information

        :param instance_id: instance id
        :param zone: zone where instance is located

        :return:
            response(json) or None
        """
        try:
            logger.info("Get GCP Instance Information: %s" % instance_id)
            request = self.compute.instances().get(
                project=self.project_id,
                zone=zone,
                instance=instance_id
            )
            response = request.execute()
            kw = kwargs.get("keyword")
            logger.debug(response)
            return response[kw] if kw else response
        except Exception:
            logger.error("Failed to get gcp instance info", exc_info=True)
            return None

    def get_instance_ip(self, instance_id, zone, **kwargs):
        """Get public ip and private ip from GCP instance

        :param instance_id: instance id
        :param zone: zone where instance is located

        :return:
            public_ip(str)
            private_ip(str)
        """
        # print(**kwargs)
        rsp = self.get_instance_info(instance_id, zone, **kwargs)
        try:
            public_ip = rsp["networkInterfaces"][0]["accessConfigs"][0]["natIP"]
        except Exception:
            public_ip = ""
        try:
            private_ip = rsp["networkInterfaces"][0]["networkIP"]
        except Exception:
            private_ip = ""
        return public_ip, private_ip
