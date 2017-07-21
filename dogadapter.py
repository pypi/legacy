import os

from datadog import initialize
from datadog.dogstatsd import DogStatsd

import config

root = os.path.dirname(os.path.abspath(__file__))
conf = config.Config(os.path.join(root, "config.ini"))

dogstatsd = DogStatsd(host='localhost', port=conf.datadog_dogstatsd_port, constant_tags=conf.datadog_tags)
