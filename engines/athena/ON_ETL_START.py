import logging.config

logging.config.fileConfig('logging.conf')
logging.info(f'Athena: no op in {__file__}')
