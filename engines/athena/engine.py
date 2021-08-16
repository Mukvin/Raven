import os
import time

import yaml

import gl
import logging
from pyathenajdbc import connect


class Engine:

    def __init__(self) -> None:
        dir = os.path.dirname(__file__)
        with open(os.path.join(dir, "athena_config.yaml"), encoding="UTF-8") as ac:
            athena_config = yaml.load(ac, Loader=yaml.FullLoader)
        self.conn = connect(S3OutputLocation=athena_config["AWS_ATHENA_S3_STAGING_DIR"],
                            AwsRegion=athena_config["AWS_REGION"])
        self.print_result = athena_config['PRINT_RESULT']

    def launch_cluster(self):
        logging.info(f'Athena: no op in launch_cluster')
        pass

    def prepare_historical_data(self):
        logging.info(f'Athena: no op in prepare_historical_data')
        pass

    # on failed queries, exceptions MUST be raised!
    def accept_query(self, sql) -> float:
        start = time.time()
        with self.conn.cursor() as cursor:
            cursor.execute(sql)
            ret = cursor.fetchall()  # Just make sure the result is fetched to local
            if self.print_result:
                logging.info(ret)
        duration = time.time() - start
        logging.info(f'a query took {duration} to complete')
        return duration

    def destroy(self):
        self.conn.close()
#
