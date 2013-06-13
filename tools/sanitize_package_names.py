#!usr/bin/env python
import re
import os
import sys
import pickle

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

valid_name = re.compile(
                r"^([A-Z0-9]|[A-Z0-9][A-Z0-9._-]*[A-Z0-9])$",
                re.IGNORECASE,
            )


def bad_names():
    cursor.execute("""
        SELECT name from packages WHERE
        name !~* '^([A-Z0-9]|[A-Z0-9][A-Z0-9._-]*[A-Z0-9])$'
    """)
    return set(x[0] for x in cursor.fetchall())

renamed = []

junk_names = bad_names()
print("Found %s bad names" % len(junk_names))

print("Rename packages where the only invalid name is a space")
for name in junk_names:
    if name.strip() != name:
        continue

    if valid_name.search(name.replace(" ", "-")) is not None:
        new_name = re.sub("\s+", "-", name)
        renamed.append((name, new_name))
        store.rename_package(name, new_name)
    else:
        new_name = re.sub("[^A-Za-z0-9.]+", "-", name).strip("_-.")
        if valid_name.search(new_name) is None:
            continue
        num = 2
        onew_name = new_name
        while [x for x in store.find_package(new_name) if x != name]:
            new_name = "%s%s" % (onew_name, str(num))
            num += 1
        renamed.append((name, new_name))
        store.rename_package(name, new_name)

with open("renamed.pkl", "w") as pkl:
    pickle.dump(renamed, pkl)

# Commit the changes
store.commit()

junk_names = bad_names()
print("Found %s bad names" % len(junk_names))
