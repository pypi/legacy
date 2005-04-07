import sys, os, re, psycopg, ConfigParser, urlparse, gzip, bz2
from mx.DateTime import DateTime
from mx.DateTime.Timezone import utc_offset

logre=re.compile(r"\[(?P<day>..)/(?P<month>...)/(?P<year>....):"
                   r"(?P<hour>..):(?P<min>..):(?P<sec>..) "
                   r'(?P<zone>.*)\] "GET (?P<path>[^ "]+) HTTP/1.." 200')

month_names=['jan','feb','mar','apr','may','jun',
             'jul','aug','sep','oct','nov','dec']
month_index = {}
for i in range(12):
    month_index[month_names[i]] = i+1

def main(argv):
    if len(argv) != 3:
        print "Usage: apache_count.py configfile logfile"
        raise SystemExit
    # Read config file
    p = ConfigParser.ConfigParser()
    p.read(argv[1])
    # Read server-relative URI prefix
    files_url = urlparse.urlsplit(p.get('webui', 'files_url'))[2]
    # Setup database connection
    dbname = p.get('database', 'name')
    dbuser = p.get('database', 'user')
    dbconn = psycopg.connect(database=dbname, user=dbuser)
    cursor = dbconn.cursor()

    filename = argv[2]
    if filename.endswith(".gz"):
        f = gzip.open(filename)
    elif filename.endswith(".bz2"):
        f = bz2.BZ2File(filename)
    else:
        f = open(filename)

    cursor.execute("select value from timestamps where name='http'")
    last_http = cursor.fetchone()[0]

    downloads = {}
    for line in f:
        m = logre.search(line)
        if not m:
            continue
        path = m.group('path')
        if not path.startswith(files_url):
            continue
        day = int(m.group('day'))
        month = m.group('month').lower()
        month = month_index[month]
        year = int(m.group('year'))
        hour = int(m.group('hour'))
        minute = int(m.group('min'))
        sec = int(m.group('sec'))
        date = DateTime(year, month, day, hour, minute, sec)
        zone = utc_offset(m.group('zone'))
        date = date - zone
        
        if date < last_http:
            continue

        filename = os.path.basename(path)
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
        downloads[filename] += 1

    if not downloads:
        return

    # Update the download counts
    for filename, count in downloads.items():
        cursor.execute("update release_files set downloads=%s "
                       "where filename=%s", (count, filename))
    # Update the download timestamp
    date = psycopg.TimestampFromMx(date)
    cursor.execute("update timestamps set value=%s "
                   "where name='http'", (date,))
    dbconn.commit()

if __name__=='__main__':
    main(sys.argv)
