#!/usr/bin/python
import sys
import os
import time

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

new_index = "%s-%s" % (conf.database_releases_index_name, int(time.time()))
print("creating new index %s" % (new_index,))
store = store.Store(conf)
store.open()

cursor = store._conn.cursor(cursor_factory=RealDictCursor)

cursor.execute("BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE READ ONLY DEFERRABLE")
cursor.execute("SET statement_timeout = '600s'")
cursor.execute("SELECT DISTINCT ON (name, _pypi_hidden) name, version, _pypi_ordering, _pypi_hidden, author, author_email, maintainer, maintainer_email, home_page, license, summary, description, keywords, platform, download_url FROM releases ORDER BY name, _pypi_hidden, _pypi_ordering DESC")
while True:
  releases = cursor.fetchmany(10000)
  if len(releases) == 0:
    break
  operations = []
  for release in releases:
    operations.append(json.dumps({"index": {"_index": new_index, "_type": "release", "_id": "%s-%s" % (release['name'], release['version'])}}))
    release['name_exact'] = release['name'].lower()
    operations.append(json.dumps(release))
  r = requests.post(conf.database_releases_index_url + "/_bulk", data="\n".join(operations))

actions = [{"add": {"index": new_index, "alias": conf.database_releases_index_name}}]
r = requests.get(conf.database_releases_index_url + "/*/_alias/" + conf.database_releases_index_name)
for alias, data in r.json().iteritems():
    if conf.database_releases_index_name in data['aliases'].keys():
        actions.append({"remove": {"index": alias, "alias": conf.database_releases_index_name}})

print("updating alias for %s to %s" % (conf.database_releases_index_name, new_index))
r = requests.post(conf.database_releases_index_url + "/_aliases", json={'actions': actions})
if r.status_code != 200:
    print("failed to update alias for %s to %s" % (conf.database_releases_index_name, new_index))
    sys.exit(1)

r = requests.get(conf.database_releases_index_url + "/_stats")
indicies = [i for i in r.json()['indices'].keys() if i.startswith(conf.database_releases_index_name + '-')]
for index in indicies:
    if index != new_index:
        print('deleting %s, because it is not %s' % (index, new_index))
        r = requests.delete(conf.database_releases_index_url + "/" + index)
        if r.status_code != 200:
            print('failed to delete %s' % (index))
