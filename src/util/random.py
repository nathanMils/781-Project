import random
import numpy as np

import logging

logger = logging.getLogger('util.random')

def set_seed(seed):
    """
    Set random seed for reproducibility.
    """
    logger.info(f"Setting random seed to {seed}")
    logger.debug("Setting random seed for random and numpy")
    random.seed(seed)
    np.random.seed(seed)
