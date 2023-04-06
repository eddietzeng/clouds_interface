import logging

logger = logging.getLogger(__name__)


def get_cloud_instance(csp, cred):
    """get cloud instance

    :param cred: credential retrieved by retrieve_secret()

    :return: cloud object

    For example:
            secret_name = "copilot/smoke_test/aws/xxxxx"
            cred = retrieve_secret(secret_name)[secret_name]
            cloud_obj = get_cloud_instance(csp, cred)
    """
    clouds = AbstractCloud.subclasses()
    try:
        cls = next(c for c in clouds if csp.lower() == c.normal_name())
    except StopIteration:
        logger.error("", exc_info=True)
        raise NotImplementedError("Cloud is not supported yet")
    return cls.from_credential(cred)


class AbstractCloud():
    """ Abstract cloud """
    @classmethod
    def subclasses(cls):
        """Return subclasses
        :return: subclasses
        """
        return cls.__subclasses__()

    @classmethod
    def normal_name(cls):
        """Return class name in lower case
        :return: class name
        """
        return cls.__name__.lower()
    
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
        return cls(cred)
