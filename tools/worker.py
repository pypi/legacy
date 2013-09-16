#!/usr/bin/env python
import os
import os.path
import sys

import raven
import redis
import rq
import rq.contrib.sentry

# Workaround current bug in docutils:
# http://permalink.gmane.org/gmane.text.docutils.devel/6324
import docutils.utils

# Make sure our PyPI directory is on the sys.path
root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path = [root] + sys.path

import config

conf = config.Config(os.environ.get("PYPI_CONFIG", "/data/pypi/config.ini"))
redis_conn = redis.Redis.from_url(conf.redis_url)

# Create our queues
if sys.argv[1:]:
    queues = [rq.Queue(name, connection=redis_conn) for name in sys.argv[1:]]
else:
    queues = [rq.Queue(connection=redis_conn)]

# Create our Worker
worker = rq.Worker(queues, connection=redis_conn)

# Create our Sentry Client
if conf.sentry_dsn:
    raven_client = raven.Client(conf.sentry_dsn)
    rq.contrib.sentry.register_sentry(raven_client, worker)

# Run our worker, fetching jobs from the queue
worker.work()
