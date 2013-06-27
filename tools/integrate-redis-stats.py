#!/usr/bin/env python
import os
import sys
import datetime
import redis

from itertools import izip, izip_longest

# Workaround current bug in docutils:
# http://permalink.gmane.org/gmane.text.docutils.devel/6324
import docutils.utils

root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path = [root] + sys.path

import store
import config

redis = redis.Redis()

# Get our search for the previous hour keys
current = datetime.datetime.utcnow()
lasthour = current - datetime.timedelta(hours=1)
search = "downloads:hour:%s:*:*" % lasthour.strftime("%y-%m-%d-%H")

# Make sure we haven't integrated this already
if redis.sismember("downloads:integrated", search):
    print("Already Integrated '%s'" % search)
    sys.exit(0)

# Fetch all of the keys
keys = redis.keys(search)

if not keys:
    print("No keys match '%s'" % search)
    sys.exit(0)

# Fetch all of the download counts (in batches of 200)
counts = []
for batch in izip_longest(*[iter(keys)] * 200):
    batch = [x for x in batch if x is not None]
    counts.extend(redis.mget(*batch))

# Combine the keys with the counts
downloads = izip(
                (int(y) for y in counts),
                (x.split(":")[-1] for x in keys),
            )

# Update the database
c = config.Config("/data/pypi/config.ini")
store = store.Store(c)
cursor = store.get_cursor()
cursor.executemany(
    "UPDATE release_files SET downloads = downloads + %s WHERE filename = %s",
    downloads,
)
cursor.commit()
cursor.close()

# Add this to our integrated set
redis.sadd("downloads:integrated", search)
