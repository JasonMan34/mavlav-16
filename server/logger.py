import logging
import os

log_level = logging.DEBUG if os.getenv('DEBUG') else logging.INFO

logging.basicConfig(level=log_level, format='%(levelname)s - %(message)s')
logger = logging.getLogger()
