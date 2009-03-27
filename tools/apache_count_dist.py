#!/usr/bin/python
try:
    import psycopg
except ImportError:
    import psycopg2 as psycopg
    psycopg.TimestampFromMx = lambda x: x 

import sys, os, ConfigParser, urlparse
import datetime
import urlparse
from mx.DateTime import DateTime
from mx.DateTime.Timezone import utc_offset
from itertools import chain

from apache_reader import ApacheLogReader
from apache_stats import ApacheDistantLocalStats
from apache_stats import LocalStats
from apache_stats import ApacheLocalStats

def get_cursor(config):
    """Setup database connection."""
    dbname = config.get('database', 'name')
    dbuser = config.get('database', 'user')
    dbpass = config.get('database', 'password')
    dbconn = psycopg.connect(database=dbname, user=dbuser, password=dbpass)
    return dbconn, dbconn.cursor()

def _log(msg):
    print msg
    sys.stdout.flush()

def _dotlog(msg):
    sys.stdout.write(msg)
    sys.stdout.flush()

def main(config_file, logfile):
    """Populate the download counts."""
    # Read config file
    p = ConfigParser.ConfigParser()
    p.read(config_file)

    # Read mirror infos
    mirrors = p.get('mirrors', 'folder')

    # Read server-relative URI prefix
    files_url = urlparse.urlsplit(p.get('webui', 'files_url'))[2]
    # Setup database connection
    dbconn, cursor = get_cursor(p)

    # create a log reader, that filters on files_url
    # build an iterator here with chain and all distant files
    cursor.execute("select * from mirrors")
    def read_distant_stats(mirror, filename):
        mirror_domain = urlparse.urlparse(mirror[0])[1]
        mirror_domain = os.path.join(mirrors, mirror_domain)
        distant_reader = ApacheDistantLocalStats(mirror_domain)
        stat_file_url = '%s/%s/%s' % (mirror[0], mirror[3], filename)
        return distant_reader.read_stats(stat_file_url)

    # it supposes it runs the program at day + 1
    yesterday = datetime.datetime.now() - datetime.timedelta(1)
    filename = yesterday.strftime('%Y-%m-%d.bz2')
    mirrors = [read_distant_stats(mirror, filename) 
               for mirror in cursor.fetchall()]

    logs = chain(*[ApacheLogReader(logfile, files_url)] + mirrors)
    _log('Working with local stats and %d mirror(s)' % len(mirrors))

    # get last http access
    cursor.execute("select value from timestamps where name='http'")
    last_http = cursor.fetchone()[0]
    _log('Last time stamp was : %s' % last_http)

    downloads = {}

    # let's read the logs in the apache file
    for line in logs:
        day = int(line.get('day', yesterday.day))
        month = line.get('month', yesterday.month)
        year = int(line.get('year', yesterday.year))
        hour = int(line.get('hour', 0))
        minute = int(line.get('min', 0))
        sec = int(line.get('sec', 0))
        date = DateTime(year, month, day, hour, minute, sec)
        zone = utc_offset(line.get('zone', 0))
        date = date - zone
        count = int(line.get('count', 1))
        if date < last_http:
            continue
        
        filename = line['filename']
    
        _dotlog('.')
        # see if we have already read the old download count
        if not downloads.has_key(filename):
            cursor.execute("select downloads from release_files "
                           "where filename=%s", (filename,))
            record = cursor.fetchone()
            if not record:
                # No file entry. Could be a .sig file
                continue
            # make sure we're working with a number
            downloads[filename] = record[0] or 0
        # add a download
        downloads[filename] += count

    if downloads != []:

        for filename, count in downloads.items():
            # Update the download counts in the DB
            _log('Updating download count for %s: %s' % (filename, count))
            cursor.execute("update release_files set downloads=%s "
                        "where filename=%s", (count, filename))
        
        # Update the download timestamp
        date = psycopg.TimestampFromMx(datetime.datetime.now())
        cursor.execute("update timestamps set value=%s "
                    "where name='http'", (date,))

        dbconn.commit()

    # now creating the local stats file
    _log('Building local stats file')
    stats = ApacheLocalStats()
    stats_dir = p.get('mirrors', 'local-stats')
    if not os.path.exists(stats_dir):
        raise ValueError('"%s" folder not found (local-stats in config.ini)' \
                    % stats_dir)
    stats_file = os.path.join(stats_dir, filename) 
    stats.build_daily_stats(yesterday.year, yesterday.month, yesterday.day,
                            logfile, stats_file, files_url, 'bz2')


    # now creating the global stats file
    # which is built with the latest database counts
    _log('Building global stats file')
    globalstats_dir = p.get('mirrors', 'global-stats')   
    if not os.path.exists(globalstats_dir):
        raise ValueError('"%s" folder not found (global-stats in config.ini)' \
                % globalstats_dir)
    cursor.execute("select name, filename, downloads from release_files")

    def get_line(files_url):
        for line in cursor:
            data = {}
            data['day'] = yesterday.day
            data['month'] = yesterday.month
            data['year'] = yesterday.year
            data['filename'] = line[1]
            data['useragent'] = 'Unkown' # not stored yet
            data['packagename'] = line[0]
            data['count'] = line[2]
            yield data

    gstats = LocalStats()
    stats_file = os.path.join(globalstats_dir, filename) 
    gstats.build_daily_stats(yesterday.year, yesterday.month, yesterday.day,
                             get_line, stats_file, files_url, 'bz2')


if __name__=='__main__':
    if len(sys.argv) != 3:
        print "Usage: apache_count.py configfile logfile"
        raise SystemExit
    main(*sys.argv[1:])

