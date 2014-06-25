#!/usr/bin/python
import sys
import os

prefix = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, prefix)

# Workaround current bug in docutils:
# http://permalink.gmane.org/gmane.text.docutils.devel/6324
import docutils.utils

import config
import store

CONFIG_FILE = os.environ.get("PYPI_CONFIG", os.path.join(prefix, 'config.ini'))

conf = config.Config(CONFIG_FILE)
store = store.Store(conf)

cursor = store.get_cursor()

cursor.execute("delete from cookies where last_seen < now()-INTERVAL'1day';")
cursor.execute("delete from openid_sessions where expires < now();")
cursor.execute("delete from openid_nonces where created < now()-INTERVAL'1day'; ")
cursor.execute("delete from openids where name in (select name from rego_otk where date < now()-INTERVAL'7days');")
cursor.execute("delete from accounts_email where user_id in (select id from accounts_user where username in (select name from rego_otk where date < now()-INTERVAL'7days' and name not in (select user_name from roles)));")
cursor.execute("delete from accounts_user where username in (select name from rego_otk where date < now()-INTERVAL'7days' and name not in (select user_name from roles));")

store.commit()
