import logging

from pyVim.connect import SmartConnect
from pyVmomi import vim

from .base import AbstractCloud

log = logging.getLogger(__name__)


class Vmw(AbstractCloud):
    def __init__(self, cred):
        self.ip = cred["ip"]
        self.port = cred.get("port", 443)
        self.username = cred["username"]
        self.password = cred["password"]
        self._vsphere_client = None

    @property
    def vsphere_client(self):
        if not self._vsphere_client:
            try:
                self._vsphere_client = SmartConnect(
                    host=self.ip, port=self.port, user=self.username,
                    pwd=self.password, disableSslCertValidation=True)
            except Exception as exc:
                raise RuntimeError(
                    "Exception met in creating a vSphere API client to "
                    "server %s:\n%r", self.ip, exc)
        return self._vsphere_client

    def get_vms(self, predicate=None):
        """
        Returns VMs present in the vSphere environment

        :param predicate func (optional): Func defining a filter criteria to
            select VMs from all VMs
        """
        content = self.vsphere_client.content
        vimtype = [vim.VirtualMachine]
        container = content.viewManager.CreateContainerView(
            content.rootFolder, vimtype, True
        )
        vms = container.view
        container.Destroy()
        if predicate:
            vms = list(filter(predicate, vms))
        log.debug(
            "Found the following VMs matching the given predicate:\n%r", vms)
        return vms
