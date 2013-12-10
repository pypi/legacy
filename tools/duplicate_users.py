#!usr/bin/env python
import os
import sys
import itertools

# Workaround current bug in docutils:
# http://permalink.gmane.org/gmane.text.docutils.devel/6324
import docutils.utils

root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path = [root] + sys.path

import store
import config


c = config.Config("config.ini")
store = store.Store(c)
store.open()
cursor = store.get_cursor()

cursor.execute("SELECT LOWER(name) FROM users GROUP BY LOWER(name) HAVING COUNT(*) > 1")
duplicated = set([x[0] for x in cursor.fetchall()])

duplicates = {}
users = {}

for username in duplicated:
    cursor.execute("SELECT name, email, last_login FROM users WHERE LOWER(name)=LOWER(%s)", (username,))
    dups = cursor.fetchall()

    duplicates[username] = [x[0] for x in dups]

    for x in dups:
        users[x[0]] = x

print len(users), "duplicated users found with", len(duplicated), "total ci unique"

total_users = users.values()
total_names = set(x[0] for x in total_users)

delete = set(total_names)

# Exclude any user who has ever submitted a journal from deletion
cursor.execute("SELECT DISTINCT ON (submitted_by) submitted_by FROM journals")
journaled = set(x[0] for x in cursor.fetchall())
delete -= journaled

# Exclude any user who is assigned a role on a package
cursor.execute("SELECT DISTINCT ON (user_name) user_name FROM roles")
roles = set(x[0] for x in cursor.fetchall())
delete -= roles

# Exclude any user who has logged in
cursor.execute("SELECT DISTINCT ON (name) name FROM users WHERE last_login != NULL")
logged_in = set(x[0] for x in cursor.fetchall())
delete -= logged_in

if delete:
    cursor.execute("DELETE FROM users WHERE name in %s", (tuple(delete),))

store.commit()
store.close()
