from tabulate import tabulate

import logging

logger = logging.getLogger('util.tabulate')

def output_table(data, headers):
    logger.debug("Outputting table")
    print(tabulate(data, headers=headers, tablefmt="fancy_grid"))