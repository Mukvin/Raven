import logging.config
import time

from .engine import Engine

logging.config.fileConfig('logging.conf')


def hook(engine: Engine):
    time.sleep(3)
    logging.info(f'Athena: sleep 3 seconds in {__file__}')
