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

new_index = "trove-%s-%s" % (conf.database_releases_index_name, int(time.time()))
print("creating new index %s" % (new_index,))
store = store.Store(conf)
store.open()

cursor = store._conn.cursor(cursor_factory=RealDictCursor)

cursor.execute("BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE READ ONLY DEFERRABLE")
cursor.execute("SET statement_timeout = '600s'")
cursor.execute("select r.name, array_agg(distinct trove_id) as trove_classifiers, array_agg(distinct t.l2) || array_agg(distinct t.l3) || array_agg(distinct t.l4) || array_agg(distinct t.l5) as categories from release_classifiers r join releases rl on (rl.name=r.name and rl.version=r.version) join trove_classifiers t on r.trove_id=t.id where not rl._pypi_hidden group by r.name")
while True:
    packages = cursor.fetchmany(1000)
    if len(packages) == 0:
        break
    operations = []
    for package in packages:
        operations.append(json.dumps({"index": {"_index": new_index, "_type": "release_classifiers", "_id": package['name']}}))
        operations.append(json.dumps(package))
    r = requests.post(conf.database_releases_index_url + "/_bulk", data="\n".join(operations))

actions = [{"add": {"index": new_index, "alias": "trove-%s" % (conf.database_releases_index_name,)}}]
r = requests.get(conf.database_releases_index_url + "/*/_alias/" + "trove-%s" % (conf.database_releases_index_name,))
for alias, data in r.json().iteritems():
    if conf.database_releases_index_name in data['aliases'].keys():
        actions.append({"remove": {"index": alias, "alias": conf.database_releases_index_name}})

print("updating alias for %s to %s" % (conf.database_releases_index_name, new_index))
r = requests.post(conf.database_releases_index_url + "/_aliases", json={'actions': actions})
if r.status_code != 200:
    print("failed to update alias for %s to %s" % (conf.database_releases_index_name, new_index))
    sys.exit(1)

r = requests.get(conf.database_releases_index_url + "/_stats")
indicies = [i for i in r.json()['indices'].keys() if i.startswith("trove-%s" % (conf.database_releases_index_name,) + '-')]
for index in indicies:
    if index != new_index:
        print('deleting %s, because it is not %s' % (index, new_index))
        r = requests.delete(conf.database_releases_index_url + "/" + index)
        if r.status_code != 200:
            print('failed to delete %s' % (index))
