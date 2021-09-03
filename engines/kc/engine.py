import os
import time

import yaml

import logging

from .instance import KylinInstance
from .kc import launch_kc_ke


class Engine:

    def __init__(self) -> None:
        d = os.path.dirname(__file__)
        with open(os.path.join(d, "kc_config.yaml"), encoding="UTF-8") as ac:
            kc_config = yaml.load(ac, Loader=yaml.FullLoader)
        self.kc_config = kc_config
        self.kylin_instance: KylinInstance = None

    def launch_cluster(self):
        logging.info('KC: first launch KC And KE nodes')
        self.kylin_instance = launch_kc_ke(self.kc_config)

    def prepare_historical_data(self):
        pass

    # on failed queries, exceptions MUST be raised!
    def accept_query(self, db, sql, id) -> float:
        response = self.kylin_instance.client.execute_query('newworkspace', 'newproject', sql, 0, 100000)
        assert response.get('isException') is not None, f'query {id} failed'
        return 0

    def destroy(self):
        # TODO
        logging.info("KC: engine destroyed")
#
