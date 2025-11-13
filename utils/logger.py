# utils/logger.py
import logging

def get_logger(name='aura_analyzer'):
    logger = logging.getLogger(name)
    if not logger.handlers:
        ch = logging.StreamHandler()
        fm = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
        ch.setFormatter(fm)
        logger.addHandler(ch)
        logger.setLevel(logging.INFO)
    return logger
