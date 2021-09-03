from enum import Enum
from itertools import groupby

from . import lightning


class ServerMode(Enum):
    MASTER = 'master'
    ALL = 'all'
    JOB = 'job'
    QUERY = 'query'


class KylinInstance:
    facade = None
    _raw_instances = []

    def __init__(self, kc_config, **kwargs):
        self._id = kwargs.get('id', 0)
        self.kc_config = kc_config
        self._uuid = 0
        self._host = kwargs['host']
        self._port = kwargs['port']
        self._home = kwargs['home']
        self._mode = kwargs['mode']
        self._status = ''
        self._version = None

        self._prop = {}

        self._platform = 'AWSGlobal'

        self._account_name = None

        self._account_key = None

        self._identifier = kc_config['StackName']

        self._resource_group = None

        self._db_type = None

        self._deploy_mode = 'ALL'

        self._client = lightning.connect(host=self._host, port=self._port)

        self.facade = self
        self._raw_instances.append(self)

    @property
    def id(self):
        if self.facade:
            return self.facade._id
        return self._id

    @property
    def uuid(self):
        if self.facade:
            return self.facade._uuid
        return self._uuid

    @property
    def host(self):
        if self.facade:
            return self.facade._host
        return self._host

    @property
    def port(self):
        if self.facade:
            return self.facade._port
        return self._port

    @property
    def home(self):
        if self.facade:
            return self.facade._home
        return self._home

    @property
    def mode(self):
        if self.facade:
            return self.facade._mode
        return self._mode

    @property
    def status(self):
        if self.facade:
            return self.facade._status
        return self._status

    @property
    def version(self):
        if self.facade:
            return self.facade._version
        return self._version

    @property
    def prop(self):
        if self.facade:
            return self.facade._prop
        return self._prop

    @property
    def platform(self):
        if self.facade:
            return self.facade._platform
        return self._platform

    @property
    def account_name(self):
        if self.facade:
            return self.facade._account_name
        return self._account_name

    @property
    def account_key(self):
        if self.facade:
            return self.facade._account_key
        return self._account_key

    @property
    def identifier(self):
        if self.facade:
            return self.facade._identifier
        return self._identifier

    @property
    def resource_group(self):
        if self.facade:
            return self.facade._resource_group
        return self._resource_group

    @property
    def db_type(self):
        if self.facade:
            return self.facade._db_type
        return self._db_type

    @property
    def deploy_mode(self):
        if self.facade:
            return self.facade._deploy_mode
        return self._deploy_mode

    @property
    def client(self):
        if self.facade:
            return self.facade._client
        return self._client

    def raw_instances(self, mode=None):
        """

        :rtype: KylinInstance[]
        """
        if mode:
            sorted_instances = sorted(self._raw_instances, key=lambda x: x.mode)
            for key, group in groupby(sorted_instances, key=lambda x: x.mode):
                if key == mode:
                    return list(group)
            return []
        return self._raw_instances

    def get(self, i):
        for ins in self.raw_instances():
            if ins.id == i:
                return ins

        raise RuntimeError(f'not found instance by id [{i}]')

    def adaptor_rw(self):
        if self.deploy_mode == 'RW':
            return self.raw_instances(mode=ServerMode.JOB.value)[0]
        return self.facade
