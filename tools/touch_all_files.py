#!/usr/bin/python
"""
This script touches all files known to the database, creating a skeletal
mirror for local development.
"""

import sys, os
import store

def get_paths(cursor, prefix=None):
    store.safe_execute(cursor, "SELECT python_version, name, filename FROM release_files")

    for type, name, filename in cursor.fetchall():
        yield os.path.join(prefix, type, name[0], name, filename)

if __name__ == '__main__':
    import config
    try:
        config = config.Config(sys.argv[1])
    except IndexError:
        print "Usage: touch_all_files.py config.ini"
        raise SystemExit

    datastore = store.Store(config)
    datastore.open()
    cursor = datastore.get_cursor()
    prefix = config.database_files_dir

    for path in get_paths(cursor, prefix):
        dir = os.path.dirname(path)
        if not os.path.exists(dir):
            print "Creating directory %s" % dir
            os.makedirs(dir)
        if not os.path.exists(path):
            print "Creating file %s" % path
            open(path, "a").write('Contents of '+path+'\n')
