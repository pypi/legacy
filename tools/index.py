#!/usr/bin/python
import sys
import os

prefix = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, prefix)

# Workaround current bug in docutils:
# http://permalink.gmane.org/gmane.text.docutils.devel/6324
import docutils.utils

from psycopg2.extras import RealDictCursor
import json
import requests

import config
import store

CONFIG_FILE = os.environ.get("PYPI_CONFIG", os.path.join(prefix, 'config.ini'))

conf = config.Config(CONFIG_FILE)

if conf.database_releases_index_name is None or conf.database_releases_index_url is None:
    sys.exit()

store = store.Store(conf)
store.open()

cursor = store._conn.cursor(cursor_factory=RealDictCursor)

cursor.execute("SELECT name, version, _pypi_ordering, _pypi_hidden, author, author_email, maintainer, maintainer_email, home_page, license, summary, description, keywords, platform, download_url FROM releases")
while True:
  releases = cursor.fetchmany(1000)
  if len(releases) == 0:
    break
  operations = []
  for release in releases:
    operations.append(json.dumps({"index": {"_index": conf.database_releases_index_name, "_type": "release", "_id": "%s-%s" % (release['name'], release['version'])}}))
    release['name_exact'] = release['name'].lower()
    operations.append(json.dumps(release))
  r = requests.post(conf.database_releases_index_url + "/_bulk", data="\n".join(operations))
