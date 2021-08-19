import os
import time

import yaml

import logging

from .athena_helper import AthenaQuery


class Engine:

    def __init__(self) -> None:
        d = os.path.dirname(__file__)
        with open(os.path.join(d, "athena_config.yaml"), encoding="UTF-8") as ac:
            athena_config = yaml.load(ac, Loader=yaml.FullLoader)
        self.outputLocation = athena_config["AWS_ATHENA_S3_STAGING_DIR"]
        self.region = athena_config["AWS_REGION"]
        self.print_result = athena_config['PRINT_RESULT']

    def launch_cluster(self):
        logging.info(f'Athena: no op in launch_cluster')
        pass

    def prepare_historical_data(self):
        logging.info(f'Athena: no op in prepare_historical_data')
        pass

    # on failed queries, exceptions MUST be raised!
    def accept_query(self, db, sql) -> float:
        start = time.time()

        my_query = AthenaQuery(
            sql,
            db,
            self.outputLocation
        )

        my_query.execute()
        result_data = my_query.get_result()

        logging.info(f"result rows: {len(result_data['ResultSet']['Rows'])}")
        if self.print_result:
            logging.info(result_data)

        duration = time.time() - start
        logging.info(f'a query took {duration} to complete')
        return duration

    def destroy(self):
        logging.info("engine destroyed")
#
