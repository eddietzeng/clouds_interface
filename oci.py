import oci
import time
import logging

from .base import AbstractCloud

logger = logging.getLogger(__name__)


class OCI(AbstractCloud):
    def __init__(self, compartment_id, config=None):
        """OCI Initilization

        :param compartment_id (str)
        :param config (dictionary):
        I.
            config = {
                "user": user_ocid,
                "key_content": key_content,
                "fingerprint": fingerprint,
                "tenancy": tenancy,
                "region": region
            }
        II.
            config = {
                "user": user_ocid,
                "key_file": key_file,
                "fingerprint": calc_fingerprint(key_file),
                "tenancy": tenancy,
                "region": region
            }
        """
        super(OCI, self).__init__()
        self.compartmentid = compartment_id
        self.config_file = oci.config.from_file(
            file_location="~/.oci/config_file") if not config else config
        self._compute_client = None
        self._network_client = None

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
        compartment_id = cred["compartment_id"]
        config = dict(
            user=cred["user_ocid"],
            key_content=cred["key_content"],
            fingerprint=cred["fingerprint"],
            tenancy=cred["tenancy_ocid"],
            region=cred["region"]
        )
        return cls(compartment_id, config)

    @property
    def compute_client(self):
        if self._compute_client is None:
            self._compute_client = oci.core.ComputeClient(self.config_file)
        return self._compute_client

    @property
    def network_client(self):
        if self._network_client is None:
            self._network_client = oci.core.VirtualNetworkClient(
                self.config_file)
        return self._network_client

    def start_instance(self, instance_id, region=None, **kwargs):
        """Start OCI instance

        :param instance_id(str): instance id to be starting
        :param region(str): region where instance is located

        wait_until() will block the current thread until either the state change to RUNNING
        or the maximum wait time(default is 1200 secs) is reached.

        """
        try:

            logger.info("Start OCI Instance: %s" % instance_id)
            response = self.compute_client.instance_action(
                instance_id, "START")
            if response.status == 200:
                logger.info(
                    "Start OCI Instance: %s" % instance_id)
                oci.wait_until(
                    self.compute_client,
                    self.compute_client.get_instance(instance_id),
                    "lifecycle_state",
                    "RUNNING"
                )
        except Exception as e:
            logger.info("Failed to start oci instance", exc_info=True)
            raise RuntimeError(e)

    def stop_instance(self, instance_id, region=None, **kwargs):
        """Stop OCI instance

        :param instance_id(str): instance id to be stopping
        :param region(str): region where instance is located

        wait_until() will block the current thread until either the state change to STOPPED
        or the maximum wait time(default is 1200 secs) is reached.
        """
        try:
            logger.info("Stop OCI Instance: %s" % instance_id)
            max_wait_secs = kwargs.get("max_wait_secs", 600)
            succeed_if_not_found = kwargs.get("succeed_if_not_found", True)
            response = self.compute_client.instance_action(instance_id, "STOP")
            if response.status == 200:
                oci.wait_until(
                    self.compute_client,
                    self.compute_client.get_instance(instance_id),
                    'lifecycle_state',
                    'STOPPED',
                    max_wait_seconds=max_wait_secs,
                    succeed_on_not_found=succeed_if_not_found
                )
        except Exception as e:
            logger.error("Failed to stop oci instance", exc_info=True)
            raise RuntimeError(e)

    def get_instance_ip(self, instance_id, region=None):
        """Get public ip and private ip from OCI instance

        :param instance_id(str): instance id
        :param region(str): region where instance is located

        :return:
            public_ip(str)
            private_ip(str)
        """
        try:
            response = self.compute_client.list_vnic_attachments(
                compartment_id=self.compartmentid,
                instance_id=instance_id
            )
            if response.status == 200:
                for vnic_attachment in response.data:
                    vnic = self.network_client.get_vnic(
                        vnic_attachment.vnic_id).data
                    public_ip = vnic.public_ip if vnic.public_ip else ""
                    private_ip = vnic.private_ip if vnic.private_ip else ""
                    return public_ip, private_ip
        except Exception:
            logger.error("Failed to get oci instance ip", exc_info=True)
            return None

    def list_route_tables(self, region_name, vcn_id):
        '''
        Function to list the route tables
        params:
        vcn_id(str): ID of the vcn network
        '''
        self.network_client.base_client.set_region(region_name)
        logger.info("Setting  the region to %s" % region_name)
        try:
            list_route_tables = self.network_client.list_route_tables(compartment_id=self.compartmentid,
                                                                      vcn_id=vcn_id)
            if list_route_tables.status == 200:
                logger.info("Showing Route Tables %s for VCN %s" %
                            (list_route_tables.data, vcn_id))
        except Exception as e:
            error_msg = "Fail to list the route table"
            logger.error(error_msg, exc_info=True)
        return list_route_tables.data

    def get_route_table(self, route_table_id):
        '''
        Function to get the route tables
        params:
        route_table_id(str): ID of the route_table
        '''
        try:
            logger.info("Fetching Info for Route Table")
            get_route_table_response = self.network_client.get_route_table(
                rt_id=route_table_id)
            if get_route_table_response.status == 200:
                logger.info("Route Table Data: %s" % get_route_table_response.data)
        except Exception as e:
            error_msg = "Fail to Get info of the route table"
            logger.error(error_msg, exc_info=True)

    def create_secondary_cidr(self, vcn_id, cidr_block):
        '''
        Function to create secondary CIDR
        params:
        vcn_id(str): ID of the vcn network
        cidr_block(str): cidr address for the vcn
        '''
        logger.info("Adding Secondary CIDR")
        try:
            add_vcn_cidr_response = self.network_client.add_vcn_cidr(
                vcn_id=vcn_id,
                add_vcn_cidr_details=oci.core.models.AddVcnCidrDetails(
                    cidr_block=cidr_block))
            if add_vcn_cidr_response.status == 202:
                logger.info("Successfully Created Seconday CIDR in VCN")
        except Exception as e:
            error_msg = "Fail to create secondary CIDR"
            logger.error(error_msg, exc_info=True)

    def delete_secondary_cidr(self, vcn_id, cidr_block):
        '''
        Function to delete secondary CIDR
        params:
        vcn_id(str): ID of the vcn network
        cidr_block(str): cidr address for the vcn
        '''
        logger.info("Deleting Secondary CIDR")
        try:
            remove_vcn_cidr_response = self.network_client.remove_vcn_cidr(
                vcn_id=vcn_id,
                remove_vcn_cidr_details=oci.core.models.RemoveVcnCidrDetails(
                    cidr_block=cidr_block))
            if remove_vcn_cidr_response.status == 202:
                logger.info("Successfully Created Seconday CIDR in VCN")
        except Exception as e:
            error_msg = "Fail to delete secondary CIDR"
            logger.error(error_msg, exc_info=True)

    def create_additional_subnet(self, vcn_id, subnet_block, route_id, disp_name="script_subnet"):
        '''
        Function to create additional subnets
        params:
        vcn_id(str): ID of the vcn network
        subnet_block(str): cidr address for the vcn
        route_id(str): id of the route table
        display_name(str): Name of the route table that will be displayed
        '''
        logger.info("Creating Additional Subnets")
        try:
            create_subnet_response = self.network_client.create_subnet(
                create_subnet_details=oci.core.models.CreateSubnetDetails(
                    cidr_block=subnet_block,
                    compartment_id=self.compartmentid,
                    vcn_id=vcn_id,
                    display_name=disp_name,
                    route_table_id=route_id))
            if create_subnet_response.status == 200:
                logger.info("Creating additional Subnets for %s" % vcn_id)
                logger.info(create_subnet_response.data)
        except Exception as e:
            error_msg = "Fail to Create Additional Subnets"
            logger.error(error_msg, exc_info=True)

    def delete_additional_subnet(self, subnet_id):
        '''
        Function to delete additional subnets
        params:
        subnet_id(str): subnet id to be deleted
        '''
        logger.info("Deleing Additional Subnets")
        try:
            delete_subnet_response = self.network_client.delete_subnet(
                subnet_id=subnet_id)
            if delete_subnet_response.status == 200:
                logger.info("Successfully deleted the subnet")
        except Exception as e:
            error_msg = "Fail to delete additional subnets"
            logger.error(error_msg, exc_info=True)

    def create_default_route_table(self, vcn_id, igw_id, display_name):
        '''
        Function to create default route table
        params:
        vcn_id(str): ID of the vcn network
        gateway_id(str): Internet gateway ID
        '''
        logger.info("Creating default route table")
        try:
            create_route_table_response = self.network_client.create_route_table(
                create_route_table_details=oci.core.models.CreateRouteTableDetails(
                    compartment_id=self.compartmentid, display_name=display_name,
                    route_rules=[oci.core.models.RouteRule(cidr_block=None, destination='0.0.0.0/0',
                                                           destination_type='CIDR_BLOCK',
                                                           network_entity_id=igw_id)], vcn_id=vcn_id))
            if create_route_table_response.status == 200:
                logger.info("Successfully created the route table")
        except Exception as e:
            error_msg = "Fail to create default route table"
            logger.error(error_msg, exc_info=True)

    def update_route_table(self, rt_table_id, priv_ip_ocid, update_dst_cidr_block="",
                           update_dst_type="CIDR_BLOCK"):
        '''
        Function to update route table with additional route rules
        params:
        rt_table_id(str): Route Table ID
        priv_ip_ocid(str): private ip address OCID
        update_dst_cidr_block(str): New Destination address
        '''
        logger.info("Updating Route Rules in the Route table")
        get_route_table_response = self.network_client.get_route_table(rt_table_id)
        route_rules_result = get_route_table_response.data.route_rules
        logger.info("Return Route Table Response: %s" % route_rules_result)
        route_rules_result.append(oci.core.models.RouteRule(cidr_block=None, destination=update_dst_cidr_block,
                                                            destination_type=update_dst_type,
                                                            network_entity_id=priv_ip_ocid))
        self.network_client.update_route_table(rt_table_id, oci.core.models.UpdateRouteTableDetails(
            route_rules=route_rules_result))
        logger.info("Updating the Route table")
        try:
            get_route_table_response = oci.wait_until(self.network_client, self.network_client.get_route_table(rt_table_id),
                                                      'lifecycle_state', 'AVAILABLE')
            if get_route_table_response.status == 200:
                logger.info("Getting Route Table Response %s" % get_route_table_response)
        except Exception as e:
            error_msg = "Fail to Update the route table"
            logger.error(error_msg, exc_info=True)

    def delete_route_table(self, route_table_id):
        '''
        Function to delete route table
        params:
        rt_table_id(str): ID of the route table
        '''
        logger.info("Deleting the Route Table")
        try:
            delete_route_table_response = self.network_client.delete_route_table(
                rt_id=route_table_id)
            if delete_route_table_response.status == 204:
                logger.info("Successfully deleted the Route Table")
        except Exception as e:
            error_msg = "Fail to delete the route table"
            logger.error(error_msg, exc_info=True)
