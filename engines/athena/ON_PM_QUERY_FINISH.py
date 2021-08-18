import logging.config
from .engine import Engine

logging.config.fileConfig('logging.conf')


def hook(engine: Engine):
    logging.info(f'Athena: no op in {__file__}')
