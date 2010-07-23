#!/usr/bin/python
import os
dbpath = "packages.db"

if os.path.exists(dbpath):
    print "Remove",dbpath,"first"
    raise SystemExit

print "Creating database", dbpath
sqlite = os.popen('sqlite3 '+dbpath, "w")
passthrough = True
for line in open('pkgbase_schema.sql'):
    if 'nosqlite-end' in line:
        # end of disabled block
        passthrough = True
        print >>sqlite
        continue
    if 'nosqlite' in line:
        passthrough = False
        print >>sqlite
        continue
    if not passthrough:
        print >> sqlite
        continue
    # make sqlite happy: SERIAL is not a valid type
    sqlite.write(line.replace('SERIAL PRIMARY KEY', 'INTEGER PRIMARY KEY'))
sqlite.close()
