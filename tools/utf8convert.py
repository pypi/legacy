''' Implements a store of disutils PKG-INFO entries, keyed off name, version.
'''
import sys, os, re, psycopg, time, sha, random, types, math, stat, errno
import logging

conn = psycopg.connect(database="pypi",
            user="pypi")

cursor = conn.cursor()
cursor.execute("SELECT * FROM releases")
for release in cursor.dictfetchall():
    newitem = {}
    for k,v in release.items():
        if type(v) is str:
            newitem[k]=v.decode("latin-1").encode('utf-8')
    cols = []
    values = []
    for k,v in newitem.items():
        cols.append("%s=%%s" % k)
        values.append(v)
    cols = ",".join(cols)
    values.append(newitem['name'])
    values.append(newitem['version'])
    stmt="update releases set %s where name=%%s and version=%%s" % cols
    cursor.execute(stmt, values)
conn.commit()
