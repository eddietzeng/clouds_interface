import boto3
import time
import logging

from botocore.exceptions import ClientError

from .base import AbstractCloud

logger = logging.getLogger(__name__)


class AWS(AbstractCloud):
    def __init__(self, key, secret):
        super(AWS, self).__init__()
        self._key = key
        self._secret = secret
        self._ec2_client = None
        self._s3_client = None

    @classmethod
    def from_credential(cls, cred):
        """Return cloud object

        :param cls
        :param cred(dict): credential retrieved by retrieve_secret()

        :return: object

        For example:
            secret_name = "copilot/smoke_test/aws/xxxxx"
            cred = retrieve_secret(secret_name)[secret_name]
        """
        try:
            key, secret = cred["aws_key"], cred["aws_secret"]
            return cls(key, secret)
        except KeyError:
            logger.error(f"Invalid AWS credentials with keys: {list(cred.keys())}")
            raise

    @property
    def ec2(self):
        if self._ec2_client is None:
            self._ec2_client = boto3.Session(
                aws_access_key_id=self._key,
                aws_secret_access_key=self._secret
            )
        return self._ec2_client

    @property
    def s3(self):
        if self._s3_client is None:
            self._s3_client = boto3.Session(
                aws_access_key_id=self._key,
                aws_secret_access_key=self._secret
            )
        return self._s3_client

    def start_instance(self, instance_id, region, **kwargs):
        """Start AWS instance

        :param instance_id(str or list): instance id to be starting
        :param region(str): region where instance is located

        waiter.wait() will block the current thread until the state change to instance_status_ok.
        A error is returned after 40 failed checks.
        """
        logger.info("Start AWS Instances: %s" % instance_id)
        dryrun = kwargs.get("dryrun", False)

        ec2_client = self.ec2.client("ec2", region_name=region)
        try:
            instance_ids = instance_id if (isinstance(
                instance_id, list)) else [instance_id]
            waiter = ec2_client.get_waiter("instance_status_ok")
            ec2_client.start_instances(
                InstanceIds=instance_ids,
                DryRun=dryrun
            )
            waiter.wait(InstanceIds=instance_ids)
        except Exception as e:
            logger.error("Failed to start aws instance", exc_info=True)
            raise RuntimeError(e)

    def stop_instance(self, instance_id, region, **kwargs):
        """Stop AWS instance

        :param instance_id(str or list): instance id to be stopping
        :param region(str): region where instance is located

        waiter.wait() will block the current thread until the state change to instance_stopped.
        A error is returned after 40 failed checks.
        """
        logger.info("Stop AWS Instances: %s" % instance_id)
        dryrun = kwargs.get("dryrun", False)
        force = kwargs.get("force", True)
        ec2_client = self.ec2.client("ec2", region_name=region)
        try:
            instance_ids = instance_id if (isinstance(
                instance_id, list)) else [instance_id]
            waiter = ec2_client.get_waiter('instance_stopped')
            ec2_client.stop_instances(
                InstanceIds=instance_ids,
                DryRun=dryrun,
                Force=force
            )
            waiter.wait(InstanceIds=instance_ids)
        except Exception as e:
            logger.error("Failed to stop aws instance", exc_info=True)
            raise RuntimeError(e)

    def get_instance_ip(self, instance_id, region):
        """Get public ip and private ip from AWS instance

        :param instance_id(str or list): instance id
        :param region(str): region where instance is located

        :return:
            public_ip(str)
            private_ip(str)
        """
        # TODO: support multiple instance_ids
        if isinstance(instance_id, list) and len(instance_id) > 1:
            raise NotImplementedError(
                "return multiple instances ids is not supported yet")
        rsp = self.get_instance_info(instance_id, region)
        try:
            public_ip = rsp["Reservations"][0]["Instances"][0]["PublicIpAddress"]
        except Exception:
            public_ip = ""
        try:
            private_ip = rsp["Reservations"][0]["Instances"][0]["PrivateIpAddress"]
        except Exception:
            private_ip = ""
        return public_ip, private_ip

    def get_instance_info(self, instance_id, region, **kwargs):
        """Get AWS instance information

        :param instance_id(str or list): instance id
        :param region(str): region where instance is located

        :return:
            response(json) or None
        """
        logger.info("Get AWS Instances Info: %s" % instance_id)

        ec2_client = self.ec2.client("ec2", region_name=region)
        try:
            instance_ids = instance_id if (isinstance(
                instance_id, list)) else [instance_id]
            filter = kwargs.get("filter")
            dryrun = kwargs.get("dryrun", False)
            if filter:
                response = ec2_client.describe_instances(
                    Filters=filter,
                    InstanceIds=instance_ids,
                    DryRun=dryrun
                )
            else:
                response = ec2_client.describe_instances(
                    InstanceIds=instance_ids,
                    DryRun=dryrun
                )
            return response

        except Exception:
            logger.error("Failed to get aws instance info", exc_info=True)
            return None

    def add_ingress_rule(self, region, sg_id, rule):
        """Add Ingress Rule to Security Group

        :param sg_id(str): security id
        :param rule(list): rule to be added to ingress rule
        """
        logger.info("Add Ingress Rule: %s" % rule)

        ec2_client = self.ec2.client("ec2", region_name=region)
        try:
            data = ec2_client.authorize_security_group_ingress(
                GroupId=sg_id,
                IpPermissions=rule
            )
            logger.info('Ingress Successfully Set %s' % data)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code != "InvalidPermission.Duplicate":
                raise RuntimeError(e)
            logger.info(f"{rule} already exists")
        except Exception as e:
            logger.error("Failed to add ingress rule", exc_info=True)
            raise RuntimeError(e)
