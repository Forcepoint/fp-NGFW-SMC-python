import logging

from smc import set_stream_logger

# Common settings for examples scripts

set_stream_logger(format_string='%(asctime)s:(%(threadName)-0s):%(name)s.%(funcName)s:'
                                '%(levelname)s: %(message)s',
                  log_level=logging.INFO)
