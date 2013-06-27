#!/usr/bin/python -u
import sys
import redis
import csv
import posixpath
import datetime
import logging
import logging.handlers

from email.utils import parsedate


PRECISIONS = [
    ("hour", "%y-%m-%d-%H", datetime.timedelta(days=2)),
    ("daily", "%y-%m-%d", datetime.timedelta(days=32)),
]


logger = logging.getLogger("rsyslog-cdn")
logger.setLevel(logging.DEBUG)
logger.addHandler(logging.handlers.SysLogHandler(address="/dev/log"))

store = redis.Redis()


def make_key(precision, when, key):
    return "downloads:%s:%s:%s" % (
        precision[0], when.strftime(precision[1]), key)


def incr(when, project, filename):
    # Increment our rolling counts in Redis
    for prec in PRECISIONS:
        key = make_key(prec, when, project)
        store.incr(key)
        store.expireat(key, when + prec[2])

    # Increment our filename based bucket in Redis
    for prec in PRECISIONS:
        key = make_key(prec, when, ":".join([project, filename]))
        store.incr(key)
        store.expireat(key, when + prec[2])


def process(line):
    try:
        row = list(csv.reader([line], delimiter=" "))[0]
        path = row[7].split(" ", 1)[1]
    except Exception:
        return

    # We only care about /packages/ urls
    if not path.startswith("/packages/"):
        return

    # We need to get the Project and Filename
    directory, filename = posixpath.split(path)
    project = posixpath.basename(directory)

    # We need to get the time this request occurred
    rtime = datetime.datetime(*parsedate(row[5])[:6])

    incr(rtime, project, filename)


if __name__ == "__main__":
    line = sys.stdin.readline()
    while line:
        try:
            process(line)
        except Exception:
            logger.exception("Error occured while processing '%s'", line)
            raise
        line = sys.stdin.readline()
