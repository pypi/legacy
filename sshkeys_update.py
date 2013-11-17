#!/usr/bin/python
import os, sys

prefix = os.path.dirname(__file__)
sys.path.insert(0, prefix)

CONFIG_FILE = os.environ.get("PYPI_CONFIG", os.path.join(prefix, 'config.ini'))

import config, store, os
standalone_py = os.path.join(os.path.dirname(__file__), 'standalone.py')
c = config.Config(CONFIG_FILE)
s = store.Store(c)
cursor = s.get_cursor()
cursor.execute("lock table sshkeys in exclusive mode") # to prevent simultaneous updates
cursor.execute("select u.name,s.key from users u, sshkeys s where u.name=s.name")
lines = []
for name, key in cursor.fetchall():
    lines.append('command="%s -r %s",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty %s\n' %
                 (standalone_py, name, key))
f = open(os.path.expanduser('~submit/.ssh/authorized_keys'), 'wb')
f.write(''.join(lines))
f.close()
s.rollback()

