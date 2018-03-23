''' Implements a store of disutils PKG-INFO entries, keyed off name, version.
'''
import sys, os, time, hashlib, random
import string, datetime, binascii, urllib, urllib2, cgi
from collections import defaultdict
try:
    import sqlite3
    sqlite3_cursor = sqlite3.Cursor
except ImportError:
    sqlite3_cursor = type(None)
from defusedxml import ElementTree
import trove
from mini_pkg_resources import safe_name
# csrf modules
import hmac
from base64 import b64encode
import openid.store.sqlstore
import requests
import itertools
import readme_renderer.rst

import tasks
import packaging.version


try:
    import psycopg2
    OperationalError = psycopg2.OperationalError
    IntegrityError = psycopg2.IntegrityError
except ImportError:
    class OperationalError(Exception):
        pass


class PreviouslyUsedFilename(Exception):
    pass


class LockedException(Exception):
    pass


from perfmetrics import statsd_client_from_uri

from dogadapter import dogstatsd

def enumerate(sequence):
    return [(i, sequence[i]) for i in range(len(sequence))]

PRECISIONS = [
    ("hour", "%y-%m-%d-%H"),
    ("daily", "%y-%m-%d"),
]
def make_key(precision, datetime, key):
    return "downloads:%s:%s:%s" % (
        precision[0], datetime.strftime(precision[1]), key)


chars = string.ascii_letters + string.digits

dist_file_types = [
    ('sdist',            'Source'),
    ('bdist_dumb',       '"dumb" binary'),
    ('bdist_rpm',        'RPM'),
    ('bdist_wininst',    'MS Windows installer'),
    ('bdist_msi',        'MS Windows MSI installer'),
    ('bdist_egg',        'Python Egg'),
    ('bdist_dmg',        'OS X Disk Image'),
    ('bdist_wheel',      'Python Wheel'),
]
dist_file_types_d = dict(dist_file_types)

# This could have been done with Postgres ENUMs, however
# a) they are not extensible, and
# b) they are not supported in other databases
class dependency:
    requires = 1
    provides = 2
    obsoletes = 3
    requires_dist = 4
    provides_dist = 5
    obsoletes_dist = 6
    requires_external = 7
    project_url = 8
    by_val = {}
for k,v in dependency.__dict__.items():
    if not isinstance(v, int):
        continue
    dependency.by_val[v] = k

keep_conn = False
connection = None
keep_trove = True


def normalize_package_name(n):
    "Return lower-cased version of safe_name of n."
    return safe_name(n).lower()


def normalize_version_number(v):
    parsed = packaging.version.parse(v)
    if isinstance(parsed, packaging.version.Version):
        # We need to normalize the version, however we can't simply use the
        # str() of the parsed version because we want to remove all of the
        # trailing zeros for this.
        parts = parsed.base_version.split("!")
        parts[-1] = ".".join(reversed(list(itertools.dropwhile(lambda x: int(x) == 0, reversed(parts[-1].split("."))))))
        fixed_base = "!".join(parts)

        # Now that we have the base_version, we need to add the rest of our
        # version pieces.
        return fixed_base + str(parsed)[len(parsed.base_version):]
    else:
        return str(parsed)


class ResultRow:
    '''Turn a tuple of row values into something that may be looked up by
    both column index and name.

    Also, convert any unicode values coming out of the database into UTF-8
    encoded 8-bit strings.
    '''
    def __init__(self, cols, info=None):
        self.cols = cols
        self.cols_d = {}
        for i, col in enumerate(cols):
            self.cols_d[col] = i
        self.info = info
    def __getitem__(self, item):
        if isinstance(item, int):
            value = self.info[item]
        else:
            n = self.cols_d[item]
            value = self.info[n]
        return self.decode(value)
    def __nonzero__(self):
        return bool(self.info)
    def items(self):
        return [(col, self.decode(self.info[i]))
                for i, col in enumerate(self.cols)]
    def as_dict(self):
        d = {}
        for i, col in enumerate(self.cols):
            d[col] = self.decode(self.info[i])
        return d
    def keys(self):
        return self.cols
    def values(self):
        return map(self.decode, self.info)

    def decode(self, value):
        if value is None:
            return value
        if isinstance(value, str):
            # decode strings stored as utf-8 into unicode
            return value.decode('utf-8')
        return value

def utf8getter(n):
    def utf8get(fields):
        if fields[n] is None: return fields[n]
        return fields[n].decode('utf-8', 'replace')

    return utf8get

def itemgetter(n):
    return lambda fields:fields[n]

def FastResultRow(cols):
    """Create a ResultRow-like class that has all fields already preparsed.
    Non-UTF-8-String columns must be suffixed with !."""
    getters = {}
    _keys = []
    for i, col in enumerate(cols.split()):
        if col[-1] == '!':
            col = col[:-1]
            getter = itemgetter(i)
        else:
            getter = utf8getter(i)
        _keys.append(col)
        getters[i] = getters[col] = getter
    class _FastResultRow:
        _getters = getters
        cols = _keys

        def __init__(self, cols, info):
            self.info = info

        def __getitem__(self, index):
            try:
                return self._getters[index](self.info)
            except KeyError:
                if isinstance(index, int):
                    raise IndexError, 'row index out of range'
                raise

        def __len__(self):
            return len(self.info)

        def __nonzero__(self):
            return bool(self.info)

        def as_dict(self):
            res = {}
            for key in self.cols:
                res[key] = self[key]
            return res

        def keys(self):
            return self.cols

        def values(self):
            res = [None] * len(self.info)
            for i in xrange(len(self.info)):
                res[i] = self[i]
            return res

        def items(self):
            if not self.info:
                return []
            res = [None] * len(self.info)
            for i, col in enumerate(self.cols):
                res[i] = (col, self[col])
            return res

    return _FastResultRow

def Result(cols, sequence, type=ResultRow):
    return [type(cols, item) for item in iter(sequence)]

def safe_execute(cursor, sql, params=None):
    """Tries to safely execute the given sql

    This will try to encode the incoming parameters into UTF-8 (where
    possible).

    """
    # Fast path to no param queries
    if params is None:
        return cursor.execute(sql)

    if isinstance(cursor, sqlite3_cursor):
        sql = sql.replace('%s', "?")

    # Encode every incoming param to UTF-8 if it's a string
    safe_params = []
    for param in params:
        if isinstance(param, unicode):
            safe_params.append(param.encode("UTF-8", "replace"))
        else:
            safe_params.append(param)
    return cursor.execute(sql, safe_params)

def binary(cursor, bytes):
    if isinstance(cursor, sqlite3_cursor):
        # XXX is this correct?
        return bytes
    return psycopg2.Binary(bytes)

class StorageError(Exception):
    pass


def _format_es_fields(hit):
    name = hit['fields']['name'][0]
    version = hit['fields']['version'][0]
    summary = hit['fields'].get('summary', [None])[0]
    if summary is not None:
        summary = summary.encode('utf8')
    _pypi_hidden = hit['fields'].get('_pypi_hidden', [False])[0]
    return (name, version, summary, _pypi_hidden)

class Store:
    ''' Store info about packages, and allow query and retrieval.

        XXX update schema info ...
            Packages are unique by (name, version).
    '''
    def __init__(self, config, queue=None, redis=None, package_bucket=None):
        self.config = config
        self.username = None
        self.userip = None
        self._conn = None
        self._cursor = None
        self._trove = None
        if self.config.database_driver == 'sqlite3':
            self.true, self.false = '1', '0'
            self.can_lock = False
        else:
            self.true, self.false = 'TRUE', 'FALSE'
            self.can_lock = True

        self.queue = queue
        self.count_redis = redis

        self.statsd_uri = "statsd://127.0.0.1:8125?prefix=%s" % (config.database_name)
        self.statsd_reporter = statsd_client_from_uri(self.statsd_uri)
        self.dogstatsd = dogstatsd

        self.package_bucket = package_bucket

        self._changed_packages = set()
        self._deleted_files = set()

    def package_url(self, url_path, name, version):
        ''' return a URL for the link to display a particular package
        '''
        if not isinstance(name, str): name = name.encode('utf-8')
        if version is None:
            # changelog entry with no version
            version = ''
        else:
            if not isinstance(version, str): version = version.encode('utf-8')
            version = '/'+urllib.quote(version)
        return u'%s/%s%s'%(url_path, urllib.quote(name), version)

    def enqueue(self, func, *args, **kwargs):
        if self.queue is None:
            func(*args, **kwargs)
        else:
            self.queue.enqueue(func, *args, **kwargs)

    def download_counts(self, name):
        # Report Zero, skip redis
        download_counts = {
            "last_day": 0,
            "last_week": 0,
            "last_month": 0,
        }
        return download_counts

    def last_id(self, tablename):
        ''' Return an SQL expression that returns the last inserted row,
        where the row is in the given table.
        '''
        if self.config.database_driver == 'sqlite3':
            return 'last_insert_rowid()'
        else:
            return "currval('%s_id_seq')" % tablename

    def trove(self):
        if not self._trove:
            self._trove = trove.Trove(self.get_cursor())
        return self._trove

    def add_journal_entry(self, name, version, action, submitted_date,
                                                submitted_by, submitted_from):
        cursor = self.get_cursor()
        safe_execute(cursor, """
            INSERT INTO journals
                (name, version, action, submitted_date, submitted_by,
                    submitted_from)
            VALUES
                (%s, %s, %s, %s, %s, %s)
        """, (name, version, action, submitted_date, submitted_by,
                                                            submitted_from))
        self._add_invalidation(name)

    def store_package(self, name, version, info):
        ''' Store info about the package to the database.

        If the name doesn't exist, we add a new package with the current
        user as the Owner of the package.

        If the version doesn't exist, we add a new release, hiding all
        previous releases.

        If the name and version do exist, we just edit (in place) and add a
        journal entry.
        '''
        date = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())
        cursor = self.get_cursor()
        # see if we're inserting or updating a package
        if not self.has_package(name):
            # insert the new package entry
            cols = 'name'
            vals = '%s'
            args = (name,)

            # if a bugtracker url is provided then insert it too
            if 'bugtrack_url' in info:
                cols += ', bugtrack_url'
                vals += ', %s'
                args += (info['bugtrack_url'], )

            sql = 'insert into packages (%s) values (%s)' % (cols, vals)
            safe_execute(cursor, sql, args)

            # journal entry
            self.add_journal_entry(name, None, "create", date,
                                                self.username, self.userip)

            # first person to add an entry may be considered owner - though
            # make sure they don't already have the Role (this might just
            # be a new version, or someone might have already given them
            # the Role)
            if not self.has_role('Owner', name):
                self.add_role(self.username, 'Owner', name)

            self._add_invalidation(None)

        # extract the Trove classifiers
        classifiers = info.get('classifiers', [])
        classifiers.sort()

        # now see if we're inserting or updating a release
        message = None
        relationships = defaultdict(set)
        old_cifiers = []
        html = readme_renderer.rst.render(info.get('description', ''))
        if self.has_release(name, version):
            # figure the changes
            existing = self.get_package(name, version)

            # handle the special vars that most likely won't have been
            # submitted
            for k in ('_pypi_ordering', '_pypi_hidden', 'bugtrack_url'):
                if not info.has_key(k):
                    info[k] = existing[k]

            # figure which cols in the table to update, if any
            specials = 'name version'.split()
            old = []
            cols = []
            vals = []
            for k, v in existing.items():
                if not info.has_key(k):
                    continue
                if k not in specials and info.get(k, None) != v:
                    old.append(k)
                    cols.append(k)
                    vals.append(info[k])
            vals.extend([name, version])

            # pull out the bugtrack_url and put it in the packages table
            # instead
            if 'bugtrack_url' in cols:
                sql = 'update packages set bugtrack_url=%s where name=%s'
                safe_execute(cursor, sql, (info['bugtrack_url'], name))
                del vals[cols.index('bugtrack_url')]
                cols.remove('bugtrack_url')

            # get old classifiers list
            old_cifiers = self.get_release_classifiers(name, version)
            old_cifiers.sort()
            if info.has_key('classifiers') and old_cifiers != classifiers:
                old.append('classifiers')

            # get old classifiers list
            for kind, specifier in self.get_release_dependencies(name, version):
                relationships[kind].add(specifier)
            for nkind, skind in dependency.by_val.items():
                # numerical kinds in relationships; string kinds in info
                try:
                    new_val = set(info[skind])
                except KeyError:
                    # value not provided
                    continue
                if relationships[skind] != new_val:
                    old.append(skind)

            # no update when nothing changes
            if not old:
                return None

            # create the journal/user message
            message = 'update %s'%', '.join(old)

            # update
            if cols:
                cols = ','.join(['%s=%%s'%x for x in cols])
                safe_execute(cursor, '''update releases set %s where name=%%s
                    and version=%%s'''%cols, vals)

            # journal the update
            self.add_journal_entry(name, version, message, date,
                                                self.username, self.userip)
        else:
            # round off the information (make sure name and version are in
            # the info dict)
            info['name'] = name
            info['version'] = version

            # figure the ordering
            info['_pypi_ordering'] = self.fix_ordering(name, version)

            # perform the insert
            cols = ('name version author author_email maintainer '
                    'maintainer_email home_page license summary description '
                    'keywords platform requires_python '
                    'download_url _pypi_ordering _pypi_hidden').split()
            args = tuple([info.get(k, None) for k in cols])
            params = ','.join(['%s']*len(cols))
            scols = ','.join(cols)
            sql = 'insert into releases (%s) values (%s)'%(scols, params)
            safe_execute(cursor, sql, args)

            # journal entry
            self.add_journal_entry(name, version, "new release", date,
                                                self.username, self.userip)

            # hide all other releases of this package if thus configured
            if self.get_package_autohide(name):
                safe_execute(cursor, 'update releases set _pypi_hidden=%s where '
                             'name=%s and version <> %s', (self.true, name, version))

        # add description urls
        if html:
            # grab the packages hosting_mode
            hosting_mode = self.get_package_hosting_mode(name)

            if hosting_mode in ["pypi-scrape-crawl", "pypi-scrape"]:
                self.update_description_urls(name, version, get_description_urls(html))

        # handle trove information
        if info.has_key('classifiers') and old_cifiers != classifiers:
            safe_execute(cursor, 'delete from release_classifiers where name=%s'
                ' and version=%s', (name, version))
            for classifier in classifiers:
                safe_execute(cursor, 'select id from trove_classifiers where'
                    ' classifier=%s', (classifier, ))
                trove_id = cursor.fetchone()[0]
                safe_execute(cursor, 'insert into release_classifiers '
                    '(name, version, trove_id) values (%s, %s, %s)',
                    (name, version, trove_id))

        # handle relationship specifiers
        for nkind, skind in dependency.by_val.items():
            if not info.has_key(skind) or relationships[nkind] == set(info[skind]):
                continue
            safe_execute(cursor, '''delete from release_dependencies where name=%s
                and version=%s and kind=%s''', (name, version, nkind))
            for specifier in info[skind]:
                safe_execute(cursor, '''insert into release_dependencies (name, version,
                    kind, specifier) values (%s, %s, %s, %s)''', (name,
                    version, nkind, specifier))

        self._add_invalidation(name)

        return message

    def fix_ordering(self, name, new_version=None):
        ''' Fix the _pypi_ordering column for a package's releases.

        If "new_version" is supplied, insert it into the sequence and
        return the ordering value for it.
        '''
        cursor = self.get_cursor()
        # load up all the version strings for this package and sort them
        safe_execute(cursor,
            'select version,_pypi_ordering from releases where name=%s',
            (name,))
        all_versions = list(cursor.fetchall())

        if new_version is not None:
            all_versions.append((new_version, None))

        sorted_versions = sorted(
            all_versions,
            key=lambda x: packaging.version.parse(x[0]),
        )

        new_order = 0
        for order, (ver, current) in enumerate(sorted_versions):
            if current != order:
                safe_execute(
                    cursor,
                    """
                    UPDATE releases SET _pypi_ordering = %s
                    WHERE name = %s AND version = %s
                    """,
                    (order, name, ver),
                )
            if ver == new_version:
                new_order = order

        self._add_invalidation(name)

        # return the ordering for this release
        return new_order

    def has_package(self, name):
        ''' Determine whether the package exists in the database.

            Returns true/false.
        '''
        cursor = self.get_cursor()
        sql = 'select count(*) from packages where name=%s'
        safe_execute(cursor, sql, (name, ))
        return int(cursor.fetchone()[0])

    def find_package(self, name):
        '''Return names of packages that differ from name only in case.'''
        cursor = self.get_cursor()
        sql = 'select name from packages where normalize_pep426_name(name)=normalize_pep426_name(%s)'
        safe_execute(cursor, sql, (name, ))
        return [r[0] for r in cursor.fetchall()]

    def has_release(self, name, version):
        ''' Determine whether the release exists in the database.

            Returns true/false.
        '''
        cursor = self.get_cursor()
        sql = 'select count(*) from releases where name=%s and version=%s'
        safe_execute(cursor, sql, (name, version))
        return int(cursor.fetchone()[0])

    def get_cheesecake_index(self, index_id):
        index = {'absolute': -1,
                 'relative': -1,
                 'subindices': []}

        cursor = self.get_cursor()

        sql = 'select absolute, relative from cheesecake_main_indices where id = %d'
        safe_execute(cursor, sql, (index_id,))

        index['absolute'], index['relative'] = cursor.fetchone()

        sql = 'select name, value, details from cheesecake_subindices where main_index_id = %d'
        safe_execute(cursor, sql, (index_id,))

        for name, value, details in cursor.fetchall():
            index['subindices'].append(dict(name=name, value=value, details=details))

        index['subindices'].sort(lambda x,y: cmp(x['name'], y['name']))

        return index

    _Package = FastResultRow('''name version author author_email
            maintainer maintainer_email home_page license summary description
            keywords platform requires_python download_url
            _pypi_ordering! _pypi_hidden! cheesecake_installability_id!
            cheesecake_documentation_id! cheesecake_code_kwalitee_id! bugtrack_url!''')
    def get_package(self, name, version):
        ''' Retrieve info about the package from the database.

            Returns a mapping with the package info.
        '''
        cursor = self.get_cursor()
        sql = '''select packages.name as name, version, author,
                  author_email, maintainer, maintainer_email, home_page,
                  license, summary, description, keywords,
                  platform, requires_python, download_url, _pypi_ordering,
                  _pypi_hidden,
                  cheesecake_installability_id,
                  cheesecake_documentation_id,
                  cheesecake_code_kwalitee_id, bugtrack_url
                 from packages, releases
                 where packages.name=%s and version=%s
                  and packages.name = releases.name'''
        safe_execute(cursor, sql, (name, version))
        return self._Package(None, cursor.fetchone())

    def get_package_urls(self, name, relative=None):
        '''Return all URLS (home, download, files) for a package,

        Return list of (link, rel, label) or None if there are no releases.
        '''
        cursor = self.get_cursor()
        file_urls = []

        # uploaded files
        safe_execute(cursor,
        '''
        SELECT filename, requires_python, md5_digest, path
        FROM release_files
        ORDER BY version, filename
        WHERE release_files.name=%s
        ''', (name,))
        for fname, requires_python, md5, path in cursor.fetchall():
            # Put files first, to have setuptools consider
            # them before going to other sites
            url = self.gen_file_url('<not used arg>', name, fname, path=path, prefix=relative) + \
                "#md5=" + md5
            file_urls.append((url, "internal", fname, requires_python))
        return sorted(file_urls)

    def get_uploaded_file_urls(self, name):
        cursor = self.get_cursor()
        urls = []
        safe_execute(cursor, '''select filename, python_version, path
            from release_files where name=%s''', (name,))
        for fname, pyversion, path in cursor.fetchall():
            urls.append(self.gen_file_url(pyversion, name, fname, path=path))
        return urls

    def top_packages(self, num=None):
        cursor = self.get_cursor()
        sql = """SELECT name, SUM(downloads) AS downloads FROM release_files
                    GROUP BY name ORDER BY downloads DESC"""
        if num is not None:
            sql += " LIMIT %s"
            safe_execute(cursor, sql, (num,))
        else:
            safe_execute(cursor, sql)

        return [(p[0], p[1]) for p in cursor.fetchall()]

    _Packages = FastResultRow('name')
    def get_packages(self):
        ''' Fetch the complete list of packages from the database.
        '''
        cursor = self.get_cursor()
        safe_execute(cursor, 'select name from packages')
        return Result(None, cursor.fetchall(), self._Packages)

    def get_packages_with_serial(self):
        cursor = self.get_cursor()
        safe_execute(cursor, "SELECT name, last_serial FROM packages")
        return dict((n,i) for n, i in cursor.fetchall())

    def get_packages_utf8(self):
        '''Fetch the complete list of package names, UTF-8 encoded
        '''
        cursor = self.get_cursor()
        cursor.execute('select name from packages order by name')
        return (p[0] for p in cursor.fetchall())

    _Journal = FastResultRow('action submitted_date! submitted_by submitted_from id!')
    def get_journal(self, name, version):
        ''' Retrieve info about the package from the database.

            Returns a list of the journal entries, giving those entries
            specific to the nominated version and those entries not specific
            to any version.
        '''
        cursor = self.get_cursor()
        # get the generic stuff or the stuff specific to the version
        sql = '''select action, submitted_date, submitted_by,
            submitted_from, id from journals where name=%s and (version=%s or
           version is NULL) order by submitted_date'''
        safe_execute(cursor, sql, (name, version))
        return Result(None, cursor.fetchall(), self._Journal)

    def count_packages(self):
        ''' Determine the number of packages registered with the index.
        '''
        cursor = self.get_cursor()
        cursor.execute('select count(*) from packages')
        return int(cursor.fetchone()[0])

    _Query_Packages = FastResultRow('name version summary _pypi_ordering!')
    def query_packages(self, spec, operator='and'):
        ''' Find packages that match the spec.

            Return a list of (name, version) tuples.
        '''
        if operator not in ('and', 'or'):
            operator = 'and'
        where = []
        for k, v in spec.items():
            if k not in ['name', 'version', 'author', 'author_email',
                         'maintainer', 'maintainer_email',
                         'home_page', 'license', 'summary',
                         'description', 'keywords', 'platform',
                         'download_url']:
                continue

            if type(v) != type([]): v = [v]
            # Quote the bits in the string that need it and then embed
            # in a "substring" search. Note - need to quote the '%' so
            # they make it through the python layer happily
            v = ['%%'+s.lower().replace("'", "''")+'%%' for s in v]

            # now add to the where clause
            where.append('(' + ' or '.join(["lower(%s) LIKE '%s'"%(k,
                s.encode('utf-8')) for s in v]) + ')')
        if where:
            where = ' %s '%operator.join(where)

        if '_pypi_hidden' in spec:
            if spec['_pypi_hidden'] in ('1', 1): v = self.true
            else: v = self.false
            if where:
                where += ' AND _pypi_hidden = %s'%v
            else:
                where = '_pypi_hidden = %s'%v

        # construct the SQL
        if where:
            where = ' where ' + where
        else:
            where = ''

        # do the fetch
        cursor = self.get_cursor()
        sql = '''select name, version, summary, _pypi_ordering
            from releases %s
            order by lower(name), _pypi_ordering'''%where
        safe_execute(cursor, sql)
        return Result(None, cursor.fetchall(), self._Query_Packages)

    def search_packages(self, spec, operator='and'):
        ''' Search for packages that match the spec.

            Return a list of (name, version, summary, _pypi_ordering) tuples.
        '''
        if self.config.database_releases_index_url is None or self.config.database_releases_index_name is None:
            return self.query_packages(spec, operator=operator)

        if operator not in ('and', 'or'):
            operator = 'and'

        hidden = False
        if '_pypi_hidden' in spec:
            if spec['_pypi_hidden'] in ('1', 1):
                hidden = True

        terms = []
        for k, v in spec.items():
            if k not in ['name', 'version', 'author', 'author_email',
                         'maintainer', 'maintainer_email',
                         'home_page', 'license', 'summary',
                         'description', 'keywords', 'platform',
                         'download_url']:
                continue

            if type(v) != type([]): v = [v]
            if k == 'name':
                terms.extend(["(name:*%s* OR name_exact:%s OR name_exact:%s OR name_exact:%s)" % (s.encode('utf-8'), safe_name(s).lower().encode('utf-8'), safe_name(s).lower().replace('-', '_'), safe_name(s).lower().replace('_', '-')) for s in v])
            else:
                terms.extend(["%s:*%s*" % (k, s.encode('utf-8')) for s in v])

        join_string = ' %s '%(operator.upper())
        query_params = {
            'q': join_string.join(terms),
            'fields': 'name,summary,version,_pypi_ordering,_pypi_hidden',
            'sort': 'name,_pypi_ordering',
            'size': '10000',
            'type': 'phrase'
        }
        query_string = urllib.urlencode(query_params)

        index_url = "/".join([self.config.database_releases_index_url, self.config.database_releases_index_name])
        start_time = int(round(time.time() * 1000))
        try:
            r = requests.get(index_url + '/release/_search?' + query_string, timeout=0.5)
            data = r.json()
        except requests.exceptions.Timeout:
            self.statsd_reporter.incr('store.search-packages.timeout')
            self.dogstatsd.increment('store.search-packages.timeout')
            data = {}
        end_time = int(round(time.time() * 1000))
        self.statsd_reporter.timing('store.search-packages', end_time - start_time)
        self.dogstatsd.timing('store.search-packages', end_time - start_time)
        results = []
        if 'hits' in data.keys():
            results = [_format_es_fields(r) for r in data['hits']['hits'] if r['fields'].get('_pypi_hidden', [False])[0] == hidden]
        return Result(None, results, self._Query_Packages)

    _Classifiers = FastResultRow('classifier')
    def get_classifiers(self):
        ''' Fetch the list of valid classifiers from the database.
        '''
        cursor = self.get_cursor()
        safe_execute(cursor, 'select classifier from trove_classifiers'
            ' order by classifier')
        return Result(None, cursor.fetchall(), self._Classifiers)

    _ClassifierID = FastResultRow('classifier id')
    def get_classifier_ids(self, classifiers):
        '''Map list of classifiers to classifier IDs'''
        cursor = self.get_cursor()
        placeholders = ','.join(['%s'] * len(classifiers))
        safe_execute(cursor, 'select classifier, id from trove_classifiers '
           'where classifier in (%s)' % placeholders, classifiers)
        return dict(cursor.fetchall())

    _Release_Classifiers = FastResultRow('classifier trove_id!')
    def get_release_classifiers(self, name, version):
        ''' Fetch the list of classifiers for the release.
        '''
        cursor = self.get_cursor()
        safe_execute(cursor, '''select classifier, trove_id
            from trove_classifiers, release_classifiers where id=trove_id
            and name=%s and version=%s order by classifier''', (name, version))
        return Result(None, cursor.fetchall(), self._Release_Classifiers)

    _Release_Relationships = FastResultRow('specifier')
    def get_release_relationships(self, name, version, relationship):
        ''' Fetch the list of relationships of a particular type, either
            "requires", "provides" or "obsoletes".
        '''
        cursor = self.get_cursor()
        safe_execute(cursor, '''select specifier from release_dependencies where
            name=%s and version=%s and kind=%s''', (name, version,
                                                    getattr(dependency, relationship)))
        return Result(None, cursor.fetchall(), self._Release_Relationships)

    _Release_Dependencies = FastResultRow('kind! specifier')
    def get_release_dependencies(self, name, version):
        '''Fetch all release dependencies of a release.'''
        cursor = self.get_cursor()
        safe_execute(cursor, '''select kind, specifier from release_dependencies
           where name=%s and version=%s''', (name, version))
        return Result(None, cursor.fetchall(), self._Release_Dependencies)

    def get_release_downloads(self, name, version):
        '''Fetch current download count for a release.'''
        cursor = self.get_cursor()
        safe_execute(cursor, '''select filename, downloads from release_files where
           name=%s and version=%s''', (name, version))
        return cursor.fetchall()

    _User_Packages_Roles = FastResultRow('role_name package_name')
    def get_user_packages(self, name):
        '''Fetch all packages and roles associated to user.'''
        cursor = self.get_cursor()
        safe_execute(cursor, '''select role_name, package_name from roles where
           user_name=%s''', (name,))
        return Result(None, cursor.fetchall(), self._User_Packages_Roles)

    _Package_Roles = FastResultRow('role_name user_name')
    def get_package_roles(self, name):
        ''' Fetch the list of Roles for the package.
        '''
        cursor = self.get_cursor()
        safe_execute(cursor, '''select role_name, user_name
            from roles where package_name=%s''', (name, ))
        return Result(None, cursor.fetchall(), self._Package_Roles)

    def get_package_autohide(self, name):
        cursor = self.get_cursor()
        safe_execute(cursor, 'select autohide from packages where name=%s',
                     [name])
        return cursor.fetchall()[0][0]

    def set_package_autohide(self, name, value):
        cursor = self.get_cursor()
        safe_execute(cursor, 'update packages set autohide=%s where name=%s',
                     [value, name])

    def get_package_hosting_mode(self, name):
        cursor = self.get_cursor()
        safe_execute(cursor, 'select hosting_mode from packages where name=%s',
                     [name])
        return cursor.fetchall()[0][0]

    def _get_package_url(self, name):
        name = name.split()[0]
        cursor = self.get_cursor()
        sql = 'select * from packages where name=%s'
        safe_execute(cursor, sql, (name, ))
        exists = cursor.fetchone() is not None
        if not exists:
            return None
        return self.config.url + '/' + name

    def get_package_requires_dist(self, name, version):
        cursor = self.get_cursor()
        safe_execute(cursor, '''select specifier from release_dependencies
            where name=%s and version=%s and kind=%s''', (name, version,
                                                          dependency.requires_dist))
        packages = []
        for package in cursor.fetchall():
            pack = {'name': package[0],
                    'href': self._get_package_url(package[0])}
            packages.append(pack)
        return packages

    def get_package_provides_dist(self, name, version):
        cursor = self.get_cursor()
        safe_execute(cursor, '''select specifier from release_dependencies
            where name=%s and version=%s and kind=%s''', (name, version,
                                                          dependency.provides_dist))
        packages = []
        for package in cursor.fetchall():
            pack = {'name': package[0],
                    'href': self._get_package_url(package[0])}
            packages.append(pack)
        return packages

    def get_package_obsoletes_dist(self, name, version):
        cursor = self.get_cursor()
        safe_execute(cursor, '''select specifier from release_dependencies
            where name=%s and version=%s and kind=%s''', (name, version,
                                                          dependency.obsoletes_dist))
        packages = []
        for package in cursor.fetchall():
            pack = {'name': package[0],
                    'href': self._get_package_url(package[0])}
            packages.append(pack)
        return packages

    def get_package_requires_external(self, name, version):
        cursor = self.get_cursor()
        safe_execute(cursor, '''select specifier from release_dependencies
            where name=%s and version=%s and kind=%s''', (name, version,
                                                          dependency.requires_external))
        return [package[0] for package in cursor.fetchall()]

    def get_package_project_url(self, name, version):
        cursor = self.get_cursor()
        safe_execute(cursor, '''select specifier from release_dependencies
            where name=%s and version=%s and kind=%s''', (name, version,
                                                          dependency.project_url))
        project_urls = []
        for project in cursor.fetchall():
            project_urls.append(project[0].split(','))
        return project_urls

    def get_unique(self, iterable):
        ''' Iterate over list of (name,version,date,summary) tuples
            and return list of unique (taking name and version into
            account) elements.
        '''
        d = {}
        L = []

        for name,version,date,summary in iterable:
            k = (name, version)
            if not d.has_key(k):
                L.append((name,version,date,summary))
                d[k] = 1

        return L

    _Updated_Releases = FastResultRow('name version submitted_date! summary')
    def updated_releases(self, since):
        '''Fetch all releases younger than "since" argument.
        '''
        assert isinstance(since, int)

        cursor = self.get_cursor()
        safe_execute(cursor, '''
            select j.name,j.version,j.submitted_date,r.summary
            from journals j, releases r
            where j.version is not NULL
                  and j.action = 'new release'
                  and j.name = r.name and j.version = r.version
                  and r._pypi_hidden = '''+self.false+'''
                  and j.submitted_date > %s
            order by submitted_date desc
        ''', (time.strftime('%Y-%m-%d %H:%M:%S +0000', time.gmtime(since)),))

        return Result(None, self.get_unique(cursor.fetchall()),
                self._Updated_Releases)

    _Changelog = FastResultRow('name version submitted_date! action id!')
    def changelog(self, since, full=False):
        '''Fetch (name, version, submitted_date, action, id) since 'since'
        argument.
        '''
        assert isinstance(since, int)

        cursor = self.get_cursor()
        query = '''
            select name, version, submitted_date, action, id
            from journals j
            where j.submitted_date > %s
            order by j.submitted_date
        '''
        if not full:
            query += 'limit 50000'
        params = (time.strftime('%Y-%m-%d %H:%M:%S +0000', time.gmtime(since)),)
        safe_execute(cursor, query, params)

        return Result(None, cursor.fetchall(), self._Changelog)

    def changelog_since_serial(self, since, full=False):
        '''Fetch (name, version, submitted_date, action, id) since 'since' id
        argument.
        '''
        assert isinstance(since, int)

        cursor = self.get_cursor()
        query = '''
            select name, version, submitted_date, action, id
            from journals j where j.id > %s
            order by j.id
        '''
        if not full:
            query += 'limit 50000'
        safe_execute(cursor, query, (since,))

        return Result(None, cursor.fetchall(), self._Changelog)

    def changelog_last_serial(self):
        '''Fetch the last event's serial id.
        '''
        cursor = self.get_cursor()
        safe_execute(cursor, 'select max(id) from journals j')
        return cursor.fetchone()[0]

    def last_serial_for_package(self, package):
        cursor = self.get_cursor()
        safe_execute(
            cursor,
            "SELECT last_serial FROM packages WHERE name = %s",
            (package,),
        )
        row = cursor.fetchone()
        if row:
            return row[0]

    def changed_packages(self, since):
        "Fetch list of names of packages changed 'since'"
        assert isinstance(since, int)
        cursor = self.get_cursor()
        safe_execute(cursor, 'select distinct(name) from journals where submitted_date > %s',
                     (time.strftime('%Y-%m-%d %H:%M:%S +0000', time.gmtime(since)),))
        return [r[0] for r in cursor.fetchall()]

    def changelog_last_hour(self):
        return self.changelog(int(time.time())-3600, full=True)

    _Latest_Packages = FastResultRow('name version submitted_date! summary')
    def latest_packages(self, num=40):
        '''Fetch "number" latest packages registered, youngest to oldest.
        '''
        cursor = self.get_cursor()
        statement = '''SELECT
                p.name, r.version, p.created as submitted_date, r.summary
            FROM releases r, (
                SELECT packages.name, max_order, packages.created
                FROM packages
                JOIN (
                   SELECT name, max(_pypi_ordering) AS max_order
                    FROM releases
                    GROUP BY name
                ) mo ON packages.name = mo.name
            ) p
            WHERE p.name = r.name
              AND p.max_order = r._pypi_ordering
            ORDER BY p.created DESC
            LIMIT %d
            ''' % num

        safe_execute(cursor, statement)
        result = Result(None, cursor.fetchall()[:num],
                self._Latest_Packages)
        return result

    _Latest_Releases = FastResultRow('name version submitted_date! summary')
    def latest_releases(self, num=40):
        ''' Fetch "number" latest releases, youngest to oldest.
        '''
        cursor = self.get_cursor()

        query = """ SELECT name, version, created as submitted_date, summary
                    FROM releases
                    WHERE _pypi_hidden is false
                    ORDER BY submitted_date DESC
                    LIMIT %s
                """ % num

        safe_execute(cursor, query)
        return Result(
            None,
            self.get_unique(cursor.fetchall()),
            self._Latest_Releases,
        )

    _Latest_Updates = FastResultRow('name version submitted_date! summary')
    def latest_updates(self, num=20):
        ''' Fetch "number" latest updates, youngest to oldest.
        '''
        cursor = self.get_cursor()
        safe_execute(cursor, '''
            select j.name,j.version,j.submitted_date,r.summary
            from journals j, releases r
            where j.version is not NULL
                  and j.name = r.name and j.version = r.version
                  and r._pypi_hidden = '''+self.false+'''
            order by submitted_date desc
        ''')

        return Result(None, self.get_unique(cursor.fetchall())[:num],
                self._Latest_Updates)

    _Latest_Release = FastResultRow('''name version submitted_date! summary
            _pypi_hidden! _pypi_ordering!''')
    def get_latest_release(self, name, hidden=None):
        ''' Fetch all releses for the package name, including hidden.

        The "latest" version determined by ordering version numbers, not by
        submission date.
        '''
        args = [name, name]
        if hidden is not None:
            args.append(hidden)
            hidden = 'and _pypi_hidden = %s'
        else:
            hidden = ''
        cursor = self.get_cursor()
        safe_execute(cursor, '''
            select r.name as name, r.version as version, j.submitted_date,
                r.summary as summary, _pypi_hidden, _pypi_ordering
            from journals j, releases r
            where j.version is not NULL
                  and j.action = 'new release'
                  and j.name = %%s
                  and r.name = %%s
                  and j.version = r.version
                  %s
            order by _pypi_ordering desc
        '''%hidden, tuple(args))
        res = cursor.fetchall()
        if res is None:
            return []
        return Result(None, res, self._Latest_Release)

    _Package_Releases = FastResultRow('name version summary _pypi_hidden!')
    def get_package_releases(self, name, hidden=None):
        ''' Fetch all releses for the package name, including hidden.
        '''
        args = [name]
        if hidden is not None:
            args.append(hidden)
            hidden = 'and _pypi_hidden = %s'
        else:
            hidden = ''
        cursor = self.get_cursor()
        safe_execute(cursor, '''
            select name, version, summary, _pypi_hidden
            from releases
            where name = %%s %s
            order by _pypi_ordering desc
        '''%hidden, tuple(args))
        res = cursor.fetchall()
        if res is None:
            return []
        return Result(None, res, self._Package_Releases)

    def update_description_urls(self, name, version, urls):
        cursor = self.get_cursor()
        safe_execute(cursor, '''delete from description_urls
        where name=%s and version=%s''', (name, version))
        for url in urls:
            url = url.encode('utf-8')
            safe_execute(cursor, '''insert into description_urls(name, version, url)
            values(%s, %s, %s)''', (name, version, url))

        self._add_invalidation(name)

    def remove_release(self, name, version):
        ''' Delete a single release from the database.
        '''
        cursor = self.get_cursor()

        self._add_invalidation(name)

        # delete the files
        to_delete = []
        for file in self.list_files(name, version):
            to_delete.append(file['path'])
        self._deleted_files |= set(to_delete)

        # delete ancillary table entries
        for tab in ('files', 'dependencies', 'classifiers'):
            safe_execute(cursor, '''delete from release_%s where
                name=%%s and version=%%s'''%tab, (name, version))
        safe_execute(cursor, 'delete from description_urls where name=%s and version=%s',
               (name, version))

        # delete releases table entry
        safe_execute(cursor, 'delete from releases where name=%s and version=%s',
            (name, version))

        date = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())
        self.add_journal_entry(name, version, "remove", date,
                                                    self.username, self.userip)

    def remove_package(self, name):
        ''' Delete an entire package from the database.
        '''
        cursor = self.get_cursor()
        to_delete = []
        for release in self.get_package_releases(name):
            for file in self.list_files(name, release['version']):
                to_delete.append(file['path'])
        self._deleted_files |= set(to_delete)

        # delete ancillary table entries
        for tab in ('files', 'dependencies', 'classifiers'):
            safe_execute(cursor, 'delete from release_%s where name=%%s'%tab,
                (name, ))

        safe_execute(cursor, 'delete from description_urls where name=%s', (name,))
        safe_execute(cursor, 'delete from releases where name=%s', (name,))
        safe_execute(cursor, 'delete from roles where package_name=%s', (name,))
        safe_execute(cursor, 'delete from packages where name=%s', (name,))

        date = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())
        self.add_journal_entry(name, None, "remove", date,
                                                    self.username, self.userip)

        self._add_invalidation(name)
        self._add_invalidation(None)

    def rename_package(self, old, new):
        ''' Rename a package. Relies on cascaded updates.
        '''
        cursor = self.get_cursor()
        date = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())
        safe_execute(cursor, '''update packages set name=%s where name=%s''',
                     (new, old))
        safe_execute(cursor, '''update journals set name=%s where name=%s''',
                     (new, old))
        # move all files on disk
        sql = '''select id, blake2_256_digest, filename, path
            from release_files where name=%s'''
        safe_execute(cursor, sql, (new,))
        for fid, digest, filename, path in cursor.fetchall():
            assert digest is not None, "Cannot Move a file without a blake2 digest"
            oldname = path
            newname = self.gen_file_path(digest, filename)
            safe_execute(
                cursor,
                "update release_files set path=%s where id=%s",
                (newname, fid),
            )
            self.package_bucket.copy_key(
                os.path.join("packages", newname),
                self.package_bucket.name,
                os.path.join("packages", oldname),
            )
            self._deleted_files.add(oldname)

        self.add_journal_entry(new, None, "rename from %s" % old, date,
                                                    self.username, self.userip)

        self._add_invalidation(new)
        self._add_invalidation(old)
        self._add_invalidation(None)

    def save_cheesecake_score(self, name, version, score_data):
        '''Save Cheesecake score for a release.
        '''
        cursor = self.get_cursor()

        execute = lambda query, *args: safe_execute(cursor, query, args)
        fetchone = cursor.fetchone

        def save_main_index(main_index):
            # Insert main_index into main_indices table.
            execute('''INSERT INTO cheesecake_main_indices
                       (absolute, relative)
                       VALUES (%d, %d)''',
                    main_index[0],
                    main_index[1])
            execute('SELECT last_value FROM cheesecake_main_indices_id_seq')
            main_index_id = fetchone()[0]

            # Insert each of its subindices.
            for sub_name, sub_value, sub_details in main_index[2]:
                execute('''INSERT INTO cheesecake_subindices
                           VALUES (%d, %s, %d, %s)''',
                        main_index_id,
                        sub_name,
                        sub_value,
                        sub_details)

            return main_index_id

        def release_exists(name, version):
            execute('''SELECT *
                       FROM releases
                       WHERE name = %s AND version = %s''',
                    name,
                    version)

            if fetchone():
                return True
            return False

        def remove_indices_for_release(name, version):
            execute('''SELECT cheesecake_installability_id,
                              cheesecake_documentation_id,
                              cheesecake_code_kwalitee_id
                       FROM releases
                       WHERE name = %s AND version = %s''',
                    name,
                    version)

            main_index_ids = fetchone()
            for index in main_index_ids:
                execute('''DELETE FROM cheesecake_subindices
                           WHERE main_index_id = %d''',
                        index)
                execute('''UPDATE releases
                           SET cheesecake_installability_id=NULL,
                               cheesecake_documentation_id=NULL,
                               cheesecake_code_kwalitee_id=NULL
                           WHERE name = %s AND version = %s''',
                        name,
                        version)
                execute('''DELETE FROM cheesecake_main_indices
                           WHERE id = %d''',
                        index)

        def insert_score_for_release(name, version, installability_id, documentation_id, code_kwalitee_id):
            execute('''UPDATE releases
                       SET cheesecake_installability_id=%d,
                           cheesecake_documentation_id=%d,
                           cheesecake_code_kwalitee_id=%d
                       WHERE name = %s AND version = %s''',
                    installability_id,
                    documentation_id,
                    code_kwalitee_id,
                    name,
                    version)

        installability_id = save_main_index(score_data['INSTALLABILITY'])
        documentation_id = save_main_index(score_data['DOCUMENTATION'])
        code_kwalitee_id = save_main_index(score_data['CODE_KWALITEE'])

        # If score for a release already exist, remove it first.
        if release_exists(name, version):
            remove_indices_for_release(name, version)

        insert_score_for_release(name, version, installability_id, documentation_id, code_kwalitee_id)

        self._add_invalidation(name)


    #
    # Users interface
    #
    def has_user(self, name):
        ''' Determine whether the user exists in the database.

            Returns true/false.
        '''
        sql = "select count(*) from accounts_user where username=%s"
        cursor = self.get_cursor()
        safe_execute(cursor, sql, (name,))
        return int(cursor.fetchone()[0])

    def store_user(self, name, password, email, otk=True):
        ''' Store info about the user to the database.

            The "password" argument is passed in cleartext and sha-ed
            before storage.

            New user entries create a rego_otk entry too and return the OTK.
        '''
        cursor = self.get_cursor()

        if self.has_user(name):
            # Existing User so we will update their entries
            safe_execute(cursor,
                "SELECT id FROM accounts_user WHERE username = %s",
                (name,)
            )
            user_id = cursor.fetchone()[0]

            if password:
                # We've been given a new password for this user
                password = self.config.passlib.hash(password)
                safe_execute(cursor,
                    """UPDATE accounts_user
                        SET password = %s
                        WHERE id = %s
                    """,
                    (password, user_id)
                )

            if email:
                # We've been given a new email for this user
                sql = """
                    WITH new_values (user_id, email, "primary", verified) AS (
                        VALUES
                            (%s, %s, TRUE, FALSE)
                    ),
                    upsert AS
                    (
                        UPDATE accounts_email ae
                            set email = nv.email,
                             verified = nv.verified
                        FROM new_values nv
                        WHERE ae.user_id = nv.user_id::uuid
                            AND ae.primary = nv.primary
                        RETURNING ae.*
                    )
                    INSERT INTO accounts_email
                        (user_id, email, "primary", verified)
                    SELECT user_id::uuid, email, "primary", verified
                    FROM new_values
                    WHERE NOT EXISTS (SELECT 1
                                      FROM upsert up
                                      WHERE up.user_id = new_values.user_id::uuid
                                        AND up.primary = new_values.primary)
                """
                safe_execute(cursor, sql, (user_id, email))

        else:
            # New User so we will create new entries

            # Make sure Email addresses are unique
            safe_execute(cursor,
                "SELECT COUNT(*) FROM accounts_email WHERE email = %s",
                (email,)
            )
            if cursor.fetchone()[0] > 0:
                raise ValueError(
                        "Email address already belongs to a different user")

            # Hash our password
            hashed_pw = self.config.passlib.hash(password)

            # Create a new User
            safe_execute(cursor,
                """INSERT INTO accounts_user (
                                        username, password, last_login,
                                        is_superuser, name, is_staff,
                                        date_joined, is_active
                                    )
                    VALUES (
                                %s, %s, current_timestamp, FALSE, '', FALSE,
                                current_timestamp, FALSE
                            )
                    RETURNING id
                """,
                (name, hashed_pw)
            )

            # Get the id of the just inserted user
            user_id = cursor.fetchone()[0]

            if email:
                # We have an email address, so create an email for this user
                safe_execute(cursor,
                    """INSERT INTO accounts_email
                                        (user_id, email, "primary", verified)
                            VALUES (%s, %s, TRUE, FALSE)
                    """,
                    (user_id, email)
                )

            if otk:
                # We want an OTK so we'll generate one
                otkv = generate_random(32)
                safe_execute(cursor,
                    """INSERT INTO rego_otk (name, otk, date)
                        VALUES (%s, %s, current_timestamp)
                    """,
                    (name, otkv)
                )
                return otkv

    def user_active(self, username):
        """
        Determines if the user is active (allowed to login)
        """
        cursor = self.get_cursor()
        sql = "SELECT is_active FROM accounts_user WHERE username = %s"
        safe_execute(cursor, sql, (username,))
        return cursor.fetchone()[0]

    def activate_user(self, username):
        """
        Activates the given user
        """
        cursor = self.get_cursor()
        sql = "UPDATE accounts_user SET is_active = TRUE WHERE username = %s"
        safe_execute(cursor, sql, (username,))

    _User = FastResultRow('name password email last_login!')
    def get_user(self, name):
        ''' Retrieve info about the user from the database.

            Returns a mapping with the user info or None if there is no
            such user.
        '''
        cursor = self.get_cursor()
        sql = """SELECT username, password, email, last_login
                    FROM accounts_user u
                        LEFT OUTER JOIN accounts_email e ON (e.user_id = u.id)
                    WHERE username = %s
        """
        safe_execute(cursor, sql, (name,))
        return self._User(None, cursor.fetchone())

    def get_user_by_email(self, email):
        ''' Retrieve info about the user from the database, looked up by
            email address.

            Returns a mapping with the user info or None if there is no
            such user.
        '''
        cursor = self.get_cursor()
        sql = """SELECT username, password, email, last_login
                    FROM accounts_user u
                        LEFT OUTER JOIN accounts_email e ON (e.user_id = u.id)
                    WHERE u.id = (
                                    SELECT user_id
                                    FROM accounts_email
                                    WHERE email = %s
                                )
        """
        safe_execute(cursor, sql, (email,))
        return self._User(None, cursor.fetchone())

    def get_user_by_openid(self, openid):
        ''' Retrieve info about the user from the database, looked up by
            email address.

            Returns a mapping with the user info or None if there is no
            such user.
        '''
        cursor = self.get_cursor()
        sql = """SELECT username, password, email, last_login
                    FROM accounts_user u
                        LEFT OUTER JOIN accounts_email e ON (e.user_id = u.id)
                    WHERE u.username = (
                                    SELECT name FROM openids WHERE id = %s
                                )
        """

        safe_execute(cursor, sql, (openid,))
        return self._User(None, cursor.fetchone())

    def get_user_by_openid_sub(self, openid_sub):
        ''' Retrieve info about the user from the database, looked up by
            email address.

            Returns a mapping with the user info or None if there is no
            such user.
        '''
        cursor = self.get_cursor()
        sql = """SELECT username, password, email, last_login
                    FROM accounts_user u
                        LEFT OUTER JOIN accounts_email e ON (e.user_id = u.id)
                    WHERE u.username = (
                                    SELECT name FROM openids WHERE sub = %s
                                )
        """

        safe_execute(cursor, sql, (openid_sub,))
        return self._User(None, cursor.fetchone())

    _Users = FastResultRow('name email')
    def get_users(self):
        ''' Fetch the complete list of users from the database.
        '''
        cursor = self.get_cursor()
        sql = """SELECT username, email
                    FROM accounts_user, accounts_email
                    WHERE accounts_user.id = accounts_email.user_id
                    ORDER BY username
        """
        safe_execute(cursor, sql)
        return Result(None, cursor.fetchall(), self._Users)

    _Openid = FastResultRow('id')
    def get_openids(self, username):
        cursor = self.get_cursor()
        safe_execute(cursor, 'select id from openids where name=%s', (username,))
        return Result(None, cursor.fetchall(), self._Openid)

    _Sshkey = FastResultRow('id! key')
    def get_sshkeys(self, username):
        '''Fetch the list of SSH keys for a user.
        '''
        cursor = self.get_cursor()
        safe_execute(cursor, 'select id,key from sshkeys where name=%s', (username,))
        return Result(None, cursor.fetchall(), self._Sshkey)

    def add_sshkey(self, username, key):
        '''Add a new SSH key for a user.
        '''
        cursor = self.get_cursor()
        safe_execute(cursor, 'insert into sshkeys(name, key) values(%s, %s)', (username, key))

    def delete_sshkey(self, id):
        '''Delete an SSH key given by ID.
        '''
        cursor = self.get_cursor()
        safe_execute(cursor, 'delete from sshkeys where id=%s', (id,))

    def has_role(self, role_name, package_name=None, user_name=None):
        ''' Determine whether the current user has the named Role for the
            named package.
        '''
        if user_name is None:
            user_name = self.username
        if user_name is None:
            return 0
        sql = '''select count(*) from roles where user_name=%s and
            role_name=%s and (package_name=%s or package_name is NULL)'''
        cursor = self.get_cursor()
        safe_execute(cursor, sql, (user_name, role_name, package_name))
        return int(cursor.fetchone()[0])

    def add_role(self, user_name, role_name, package_name):
        ''' Add a role to the user for the package.
        '''
        cursor = self.get_cursor()
        safe_execute(cursor, '''
            insert into roles (user_name, role_name, package_name)
            values (%s, %s, %s)''', (user_name, role_name, package_name))
        date = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())
        self.add_journal_entry(
            package_name, None, "add %s %s" % (role_name, user_name), date,
            self.username, self.userip)

    def delete_role(self, user_name, role_name, package_name):
        ''' Delete a role for the user for the package.
        '''
        cursor = self.get_cursor()
        safe_execute(cursor, '''
            delete from roles where user_name=%s and role_name=%s
            and package_name=%s''', (user_name, role_name, package_name))
        date = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())
        self.add_journal_entry(
                package_name, None, "remove %s %s" % (role_name, user_name),
                date, self.username, self.userip)

    def delete_otk(self, otk):
        ''' Delete the One Time Key.
        '''
        safe_execute(self.get_cursor(), "delete from rego_otk where otk=%s",
                     (otk,))

    def get_otk(self, username):
        ''' Retrieve the One Time Key for the user.

        Username must be a case-sensitive match.
        '''
        cursor = self.get_cursor()
        safe_execute(cursor, 'select otk from rego_otk where name=%s',
            (username, ))
        res = cursor.fetchone()
        if res is None:
            return ''
        return res[0]

    def get_user_by_otk(self, otk):
        '''Find a user by its otk.
        '''
        cursor = self.get_cursor()
        safe_execute(cursor, "select name from rego_otk where otk=%s", (otk, ))
        res = cursor.fetchone()
        if res is None:
            return ''
        return res[0]

    _User_Packages = FastResultRow('package_name')
    def user_packages(self, user, only_owner=False):
        ''' Retrieve package info for all packages of a user
        '''
        cursor = self.get_cursor()
        owner_sql = ''
        if only_owner:
            owner_sql = "and roles.role_name='Owner'"
        sql = '''select distinct(package_name),lower(package_name) from roles
                 where roles.user_name=%s and package_name is not NULL
                 ''' + owner_sql + '''
                 order by lower(package_name)'''
        safe_execute(cursor, sql, (user,))
        res = cursor.fetchall()
        if res is None:
            res = []
        return Result(None, res, self._User_Packages)

    def delete_user(self, user):
        '''Delete a user. Return None.'''
        cursor = self.get_cursor()
        # delete all maintainer roles
        safe_execute(cursor,
                     '''delete from roles where role_name='Maintainer'
                        and user_name=%s''',
                     (user,))
        # point all journal entries to the "deleted user"
        safe_execute(cursor,
                     '''update journals set submitted_by='deleted-user' where submitted_by=%s''',
                     (user,))
        # delete all cookies
        safe_execute(cursor,
                     '''delete from cookies where name=%s''',
                     (user,))

        safe_execute(cursor,
            "SELECT id FROM accounts_user WHERE username = %s", (user,)
        )
        user_id = cursor.fetchone()[0]

        # Delete all the users emails
        safe_execute(cursor,
            "DELETE FROM accounts_email WHERE user_id = %s", (user_id,)
        )

        # Delete all the users gpg keys
        safe_execute(cursor,
            "DELETE FROM accounts_gpgkey WHERE user_id = %s", (user_id,)
        )

        # every other reference should either be cascading,
        # or it's a bug to break it

        # delete user account itself
        safe_execute(cursor,
            "DELETE FROM accounts_user WHERE username=%s", (user,)
        )

    #
    # Trove
    #

    def check_trove(self):
        cursor = self.get_cursor()
        trove = self.trove()
        # Verify that all l2, l3, l4 fields are set properly
        for field, depth in (('l2', 2), ('l3', 3), ('l4', 4), ('l5', 5)):
            cursor.execute('select id from trove_classifiers where %s is null' % field)
            for id, in cursor.fetchall():
                t = trove.trove[id]
                if len(t.path_split) < depth:
                    value = 0
                else:
                    value = trove.getid(t.path_split[:depth])
                cursor.execute('update trove_classifiers set %s=%d where id=%d' % (field, value, id))

    def browse_tally(self):
        return self.browse([0])

    def browse(self, selected_classifiers):

        query = {
            "fields": ["name", "version", "summary"],
            "size": 200000,
            "query": {
              "filtered": {
                "query": {
                  "match_all": {}
                },
                "filter": {
                  "bool": {
                    "must": [{"term": {"categories": cat_id}} for cat_id in selected_classifiers]
                  }
                }
              }
            },
            "facets": {
              "categories": {"terms": {"field": "categories", "size": 10000}}
            }
        }

        index_url = "/".join([self.config.database_releases_index_url, "trove-%s" % (self.config.database_releases_index_name,)])

        start_time = int(round(time.time() * 1000))
        try:
            r = requests.get(index_url + "/_search", json=query, timeout=1.0)
            data = r.json()
        except requests.exceptions.Timeout:
            self.statsd_reporter.incr('store.browse.timeout')
            self.dogstatsd.increment('store.browse.timeout')
            data = {}
        end_time = int(round(time.time() * 1000))
        self.statsd_reporter.timing('store.browse', end_time - start_time)
        self.dogstatsd.timing('store.browse', end_time - start_time)

        releases = []
        tally = []
        if 'hits' in data.keys():
            for hit in data['hits']['hits']:
                name = hit['fields']['name'][0]
                summary = hit['fields'].get('summary', [''])[0]
                releases.append((name, '', summary))

        if 'facets' in data.keys():
            tally = [(f['term'], f['count']) for f in data['facets']['categories']['terms'] if f['term'] != 0]

        return releases, tally

    def get_package_from_filename(self, filename):
        query = """
            SELECT name FROM release_files
            WHERE filename = %s
            LIMIT 1
        """
        cursor = self.get_cursor()
        cursor.execute(query, [filename])
        results = cursor.fetchall()
        if results:
            return results[0][0]

    def get_digest_from_filename(self, filename):
        query = """
            SELECT md5_digest FROM release_files
            WHERE filename = %s
            LIMIT 1
        """
        cursor = self.get_cursor()
        cursor.execute(query, [filename])
        results = cursor.fetchall()
        if results:
            return results[0][0]

    #
    # File handling
    #
    def gen_file_url(self, pyversion, name, filename, path=None, prefix=None):
        '''Generate the URL for a given file download.'''
        if not prefix:
            prefix = self.config.files_url

        if path is None:
            cursor = self.get_cursor()
            safe_execute(
                cursor,
                "SELECT path FROM release_files WHERE filename = %s",
                (filename,),
            )
            results = cursor.fetchall()
            path = results[0][0]

        if path is not None:
            return os.path.join(prefix, path)

    def gen_file_path(self, digest, filename):
        '''Generate the path to the file on disk.'''

        return os.path.join(digest[:2], digest[2:4], digest[4:], filename)

    _List_Files = FastResultRow('''packagetype python_version comment_text
    filename md5_digest sha256_digest path size! has_sig! downloads! upload_time!''')
    def list_files(self, name, version, show_missing=False):
        cursor = self.get_cursor()
        sql = '''select packagetype, python_version, comment_text,
            filename, md5_digest, sha256_digest, downloads, size, has_signature, path,
            upload_time
            from release_files
            where name=%s and version=%s'''
        safe_execute(cursor, sql, (name, version))
        l = []
        for pt, pv, ct, fn, m5, s256, dn, size, has_sig, path, ut in cursor.fetchall():
            l.append(self._List_Files(None, (pt, pv, ct, fn, m5, s256, path, size, has_sig, dn, ut)))
        l.sort(key=lambda r:r['filename'])
        return l

    def has_file(self, name, version, filename):
        cursor = self.get_cursor()
        sql = '''select count(*) from release_files
            where name=%s and version=%s and filename=%s'''
        safe_execute(cursor, sql, (name, version, filename))
        return int(cursor.fetchone()[0])

    def remove_file(self, digest):
        cursor = self.get_cursor()
        sql = '''select python_version, name, version, filename, has_signature,
                 path
            from release_files
            where md5_digest=%s'''
        safe_execute(cursor, sql, (digest, ))
        info = cursor.fetchone()
        if not info:
            raise KeyError, 'no such file'
        pyversion, name, version, filename, has_sig, filepath = info
        safe_execute(cursor, 'delete from release_files where md5_digest=%s',
            (digest, ))
        self._deleted_files.add(filepath)
        if has_sig:
            self._deleted_files.add(filepath + ".asc")
        date = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())
        self.add_journal_entry(name, version, "remove file %s" % filename,
                                            date, self.username, self.userip)

        self._add_invalidation(name)

    _File_Info = FastResultRow('''python_version packagetype name comment_text
                                filename''')
    def get_file_info(self, digest):
        '''Get the file info based on the md5 hash.

        Raise KeyError if the digest doesn:t match any file in the
        database.
        '''
        cursor = self.get_cursor()
        sql = '''select python_version, packagetype, name, comment_text,
            filename from release_files where md5_digest=%s'''
        safe_execute(cursor, sql, (digest, ))
        row = cursor.fetchone()
        if not row:
            raise KeyError, 'invalid digest %r'%digest
        return self._File_Info(None, row)

    def lock_docs(self, name):
        doc_id = int(hashlib.sha256(name).hexdigest()[:8].encode("hex"), 16)
        cursor = self.get_cursor()
        sql = "SELECT pg_try_advisory_xact_lock(%s)"
        safe_execute(cursor, sql, (doc_id,))
        row = cursor.fetchone()
        if not row[0]:
            raise LockedException

    def set_has_docs(self, name, value=True):
        cursor = self.get_cursor()
        if value:
            sql = "UPDATE packages SET has_docs = 't' WHERE name = %s"
        else:
            sql = "UPDATE packages SET has_docs = 'f' WHERE name = %s"
        safe_execute(cursor, sql, (name,))

    def log_docs(self, name, version, operation=None):
        if operation is None:
            operation = 'docupdate'
        cursor = self.get_cursor()
        date = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())
        self.add_journal_entry(name, version, operation, date,
                               self.username, self.userip)

    def docs_url(self, name):
        '''Determine the local (pythonhosted.org) documentation URL, if any.

        Returns the URL or '' if there are no docs.
        '''
        cursor = self.get_cursor()
        sql = "SELECT has_docs FROM packages WHERE name = %s"
        safe_execute(cursor, sql, (name,))
        row = cursor.fetchone()
        if row[0]:
            base = self.config.package_docs_url
            if not base.endswith("/"):
                base += "/"
            return base + name + "/"

    #
    # Mirrors managment
    #
    def add_mirror(self, ip, user):
        ''' Add a mirror to the mirrors list
        '''
        cursor = self.get_cursor()
        sql = ('insert into mirrors (ip, user_name)'
               'values (%s, %s)')

        values = (ip, user)
        safe_execute(cursor, sql, values)

    def delete_mirror(self, ip):
        ''' Delete a mirror
        '''
        cursor = self.get_cursor()
        cursor.execute('delete from mirrors where ip=%s', [ip])

    def list_mirrors(self):
        ''' Returns a list of mirrors
        '''
        cursor = self.get_cursor()
        sql = '''select ip from mirrors'''
        safe_execute(cursor, sql)
        return cursor.fetchall()

    def find_user_by_cookie(self, cookie):
        '''Return username of user if cookie is valid, else None.'''
        if not cookie:
            return None
        cursor = self.get_cursor()
        sql = 'select name, last_seen from cookies where cookie=%s'
        safe_execute(cursor, sql, (cookie,))
        users = cursor.fetchall()
        if users:
            # cookie was found
            name, last_seen = users[0]
            if datetime.datetime.now()-datetime.timedelta(0,60) > last_seen:
                # refresh cookie and login time every minute
                sql = 'update cookies set last_seen=current_timestamp where cookie=%s'
                safe_execute(cursor, sql, (cookie,))
                sql ='update accounts_user set last_login=current_timestamp where username=%s'
                safe_execute(cursor, sql, (name,))
            return name
        return None

    def create_cookie(self, username):
        '''Create and return a new cookie for the user.'''
        cursor = self.get_cursor()
        cookie = binascii.hexlify(os.urandom(16))
        sql = '''insert into cookies(cookie, name, last_seen)
                 values(%s, %s, current_timestamp)'''
        safe_execute(cursor, sql, (cookie, username))
        return cookie

    def delete_cookie(self, cookie):
        cursor = self.get_cursor()
        safe_execute(cursor, 'delete from cookies where cookie=%s', (cookie,))

    # CSRF Protection

    def get_token(self, username):
        '''Return csrf current token for user.'''
        cursor = self.get_cursor()
        sql = '''select token from csrf_tokens where name=%s'''
        safe_execute(cursor, sql, (username,))
        token = cursor.fetchall()
        if not token:
            return self.create_token(username)
        return token[0][0]

    def create_token(self, username):
        '''Create and return a new csrf token for user.'''
        # dependency on cookie existence
        cursor = self.get_cursor()
        safe_execute(cursor, 'select cookie from cookies where name=%s',
                (username,))
        try:
            cookie = cursor.fetchall()[0][0]
        except IndexError:
            # no cookie, make one
            cookie = generate_random(10)

        # create random data
        rand = [generate_random(12)]
        rand.append(str(int(time.time())))
        rand.append(cookie)
        random.SystemRandom().shuffle(rand)
        rand = hmac.new(
            generate_random(16),
            ''.join(rand),
            digestmod=hashlib.sha1,
        ).hexdigest()
        rand = b64encode(rand)

        # we may have a current entry which is out of date, delete
        safe_execute(cursor, 'delete from csrf_tokens where name=%s', (username,))
        target = datetime.datetime.now() + datetime.timedelta(minutes=15)
        sql = """
            WITH new_values (name, token, end_date) AS (
                VALUES
                    (%s, %s, %s)
            ),
            upsert AS
            (
                UPDATE csrf_tokens ct
                    set token = nv.token,
                     end_date = nv.end_date
                FROM new_values nv
                WHERE ct.name = nv.name
                RETURNING ct.*
            )
            INSERT INTO csrf_tokens (name, token, end_date)
            SELECT name, token, end_date
            FROM new_values
            WHERE NOT EXISTS (SELECT 1
                              FROM upsert up
                              WHERE up.name = new_values.name)
        """
        safe_execute(cursor, sql, (username, rand, target))

        return rand

    # OpenID

    def find_association(self, assoc_handle):
        cursor = self.get_cursor()
        sql ='select mac_key from openid_sessions where assoc_handle=%s'
        safe_execute(cursor, sql, (assoc_handle,))
        sessions = cursor.fetchall()
        if sessions:
            return {'assoc_handle':assoc_handle, 'mac_key':sessions[0][0]}
        return None

    def associate_openid(self, username, openid):
        cursor = self.get_cursor()
        safe_execute(cursor, 'insert into openids(id, name) values(%s,%s)',
                     (openid, username))

    def migrate_to_openid_sub(self, username, openid, openid_sub):
        cursor = self.get_cursor()
        safe_execute(cursor, 'update openids set sub=%s where id=%s and name=%s',
                     (openid_sub, openid, username))

    def drop_openid(self, openid):
        cursor = self.get_cursor()
        safe_execute(cursor, 'delete from openids where id=%s', (openid,))

    def check_openid_trustedroot(self, username, trusted_root):
        """Check trusted_root is in user's whitelist"""
        cursor = self.get_cursor()
        safe_execute(cursor, '''select * from openid_whitelist
                                where name=%s and trust_root=%s''',
                                (username, trusted_root))
        if cursor.fetchone():
            return True
        else:
            return False

    def log_keyrotate(self):
        cursor = self.get_cursor()
        date = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())
        safe_execute(cursor, '''insert into journals (
              name, version, action, submitted_date, submitted_by,
              submitted_from) values (%s, %s, %s, %s, %s, %s)''',
            ('', '', 'keyrotate ', date,
            None, None))


    #
    # Handle the underlying database
    #
    def get_cursor(self):
        if self._cursor is None:
            self.open()
        return self._cursor

    def open(self):
        ''' Open the database, initialising if necessary.
        '''
        global connection
        # ensure files are group readable and writable
        cd = dict(database=self.config.database_name,
            user=self.config.database_user)
        if self.config.database_pw:
            cd['password'] = self.config.database_pw
        if self.config.database_host:
            cd['host'] = self.config.database_host
        if self.config.database_port:
            cd['port'] = self.config.database_port
        if keep_conn and connection:
            self._conn = connection
            # Rollback any uncommitted earlier change
            try:
                self._conn.rollback()
            except psycopg2.InterfaceError:
                # already closed
                connection = None
                return self.open()
        elif self.config.database_driver == 'sqlite3':
            self._conn = connection = sqlite3.connect(self.config.database_name,
                detect_types=sqlite3.PARSE_DECLTYPES|sqlite3.PARSE_COLNAMES)
            # we store encoded strings in the db, not unicode objects
            self._conn.text_factory = str
        else:
            self._conn = connection = psycopg2.connect(**cd)

        cursor = self._cursor = self._conn.cursor()
        self._changed_packages = set()
        self._deleted_files = set()

    def set_read_only(self):
        safe_execute(
            self.get_cursor(),
            """
            SET TRANSACTION
                ISOLATION LEVEL SERIALIZABLE
                READ ONLY
                DEFERRABLE
            """,
        )

    def oid_store(self):
        if self.config.database_driver == 'sqlite3':
            return openid.store.sqlstore.SQLiteStore(self._conn)
        return openid.store.sqlstore.PostgreSQLStore(self._conn)

    def force_close(self):
        '''Force closure of the current persistent connection.
        '''
        global connection
        try:
            connection.close()
        except Exception:
            pass
        connection = None
        self._changed_packages = set()
        self._deleted_files = set()

    def set_user(self, username, userip, update_last_login):
        ''' Set the user who is doing the changes.
        '''
        # now check the user
        if username is not None:
            if self.has_user(username):
                self.username = username
                if update_last_login:
                    safe_execute(self.get_cursor(), '''update accounts_user
                        set last_login=current_timestamp
                        where username=%s''', (username,))
        self.userip = userip

    def setpasswd(self, username, password, hashed=False):
        if not hashed:
            password = self.config.passlib.hash(password)

        safe_execute(self.get_cursor(), '''update accounts_user set password=%s
            where username=%s''', (password, username))

    def _add_invalidation(self, package=None):
        self._changed_packages.add(package)

    def _invalidate_cache(self):
        # Build up a list of tags we want to purge
        tags = []
        for pkg in self._changed_packages:
            if pkg is None:
                tags += ["simple-index"]
            else:
                tags += ["pkg~%s" % safe_name(pkg).lower()]

        if self.config.fastly_api_key:
            # We only need to bother to enqueue a task if we have something
            #   to purge
            if tags:
                # Enqueue the purge
                self.enqueue(tasks.purge_fastly_tags,
                            self.config.fastly_api_domain,
                            self.config.fastly_api_key,
                            self.config.fastly_service_id,
                            tags,
                    )

        if self.config.cache_redis_url:
            if tags:
                self.enqueue(tasks.purge_redis_cache,
                             self.config.cache_redis_url,
                             tags,
                    )

        # Empty our changed packages
        self._changed_packages = set()

    def close(self):
        if self._conn is None:
            return
        if keep_conn:
            # rollback any aborted transaction
            self._conn.rollback()
        else:
            self._conn.close()
        if not keep_trove:
            self._trove = None
        self._conn = None
        self._cursor = None

    def commit(self):
        if self._conn is None:
            return
        self._conn.commit()
        self._invalidate_cache()
        self.package_bucket.delete_keys(
            list(self._deleted_files) +
            [os.path.join("packages", f) for f in self._deleted_files]
        )
        self._deleted_files = set()

    def rollback(self):
        if self._conn is None:
            return
        self._conn.rollback()
        self._cursor = None
        self._changed_packages = set()
        self._deleted_files = set()

    def changed(self):
        '''A journalled change has been made. Notify listeners'''
        self.commit()
        # XXX consider running this in a separate thread
        if self.config.pubsubhubbub:
            try:
                urllib2.urlopen(self.config.pubsubhubbub, "hub.mode=publish&hub.url="+
                                urllib2.quote(self.config.url+'?:action=lasthour'))
            except urllib2.HTTPError, e:
                if e.code == 204:
                    # no content, ok
                    return
                # ignore all other errors
            except Exception:
                pass

def generate_random(length, chars = string.letters + string.digits):
    return ''.join([random.SystemRandom().choice(chars) for n in range(length)])

def xmlescape(url):
    '''Make sure a URL is valid XML'''
    try:
        ElementTree.fromstring('<x y="%s"/>' % url)
    except ElementTree.ParseError:
        return cgi.escape(url)
    else:
        return url

def get_description_urls(html):
    from htmllib import HTMLParser
    from formatter import NullFormatter
    import urlparse, sgmllib
    try:
        parser = HTMLParser(NullFormatter())
        parser.feed(html)
        parser.close()
    except sgmllib.SGMLParseError:
        return []
    result = []
    for url in parser.anchorlist:
        if urlparse.urlparse(url)[0]:
            result.append(xmlescape(url))
    return result

if __name__ == '__main__':
    import config
    cfg = config.Config(sys.argv[1])
    store = Store(cfg)
    store.open()
    if sys.argv[2] == 'changepw':
        store.setpasswd(sys.argv[3], sys.argv[4])
        store.commit()
    elif sys.argv[2] == 'adduser':
        otk = store.store_user(sys.argv[3], sys.argv[4], sys.argv[5])
        store.delete_otk(otk)
        store.commit()
    elif sys.argv[2] == 'checktrove':
        store.check_trove()
        store.commit()
    elif sys.argv[2] == 'update_normalized_text':
        store.update_normalized_text()
        store.commit()
    elif sys.argv[2] == 'update_upload_times':
        store.update_upload_times()
        store.commit()
    else:
        print "UNKNOWN COMMAND", sys.argv[2]
    store.close()
