''' Implements a store of disutils PKG-INFO entries, keyed off name, version.
'''
import sys, os, re, psycopg, time, sha, random, types, math, stat, errno
import logging, cStringIO, string
from distutils.version import LooseVersion
import trove
from mini_pkg_resources import safe_name

def enumerate(sequence):
    return [(i, sequence[i]) for i in range(len(sequence))]


chars = string.ascii_letters + string.digits

dist_file_types = [
    ('sdist',            'Source'),
    ('bdist_dumb',       '"dumb" binary'),
    ('bdist_rpm',        'RPM'),
    ('bdist_wininst',    'MS Windows installer'),
    ('bdist_egg',        'Python Egg'),
    ('bdist_dmg',        'OS X Disk Image'),
]
dist_file_types_d = dict(dist_file_types)

keep_conn = False
connection = None
keep_trove = True

def normalize_package_name(n):
    "Return lower-cased version of safe_name of n."
    return safe_name(n).lower()

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

    # Encode every incoming param to UTF-8 if it's a string
    safe_params = []
    for param in params:
        if isinstance(param, unicode):
            safe_params.append(param.encode("UTF-8", "replace"))
        else:
            safe_params.append(param)
    return cursor.execute(sql, safe_params)

class StorageError(Exception):
    pass

class Store:
    ''' Store info about packages, and allow query and retrieval.

        XXX update schema info ...
            Packages are unique by (name, version).
    '''
    def __init__(self, config):
        self.config = config
        self.username = None
        self.userip = None
        self._conn = None
        self._cursor = None
        self._trove = None

    def trove(self):
        if not self._trove:
            self._trove = trove.Trove(self.get_cursor())
        return self._trove

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
            sql = 'insert into packages (name, normalized_name) values (%s, %s)'
            safe_execute(cursor, sql, (name, normalize_package_name(name)))

            # journal entry
            safe_execute(cursor, '''insert into journals (name, version, action,
                submitted_date, submitted_by, submitted_from) values
                (%s, %s, %s, %s, %s, %s)''', (name,
                                              None,
                                              'create',
                                              date,
                                              self.username,
                                              self.userip))

            # first person to add an entry may be considered owner - though
            # make sure they don't already have the Role (this might just
            # be a new version, or someone might have already given them
            # the Role)
            if not self.has_role('Owner', name):
                self.add_role(self.username, 'Owner', name)

        # extract the Trove classifiers
        classifiers = info.get('classifiers', [])
        classifiers.sort()

        # now see if we're inserting or updating a release
        message = None
        relationships = {}
        old_cifiers = []
        html = None
        if self.has_release(name, version):
            # figure the changes
            existing = self.get_package(name, version)

            # handle the special vars that most likely won't have been
            # submitted
            for k in ('_pypi_ordering', '_pypi_hidden'):
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
                    if k == 'description':
                        cols.append('description_html')
                        html = processDescription(info[k])
                        vals.append(html)
                    old.append(k)
                    cols.append(k)
                    vals.append(info[k])
            vals.extend([name, version])

            # get old classifiers list
            old_cifiers = self.get_release_classifiers(name, version)
            old_cifiers.sort()
            if info.has_key('classifiers') and old_cifiers != classifiers:
                old.append('classifiers')

            # get old classifiers list
            for col in ('requires', 'provides', 'obsoletes'):
                relationships[col] = self.get_release_relationships(name,
                    version, col)
                relationships[col].sort()
                new_val = info.get(col, [])
                new_val.sort()
                if info.has_key(col) and relationships[col] != new_val:
                    old.append(col)

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
            safe_execute(cursor, '''insert into journals (name, version,
                action, submitted_date, submitted_by, submitted_from)
                values (%s, %s, %s, %s, %s, %s)''', (name, version, message,
                date, self.username, self.userip))
        else:
            # round off the information (make sure name and version are in
            # the info dict)
            info['name'] = name
            info['version'] = version

            # figure the ordering
            info['_pypi_ordering'] = self.fix_ordering(name, version)

            # ReST-format the description
            if info.has_key('description'):
                info['description_html'] = html = processDescription(info['description'])
            else:
                info['description_html'] = ''

            # perform the insert
            cols = 'name version author author_email maintainer maintainer_email home_page license summary description description_html keywords platform download_url _pypi_ordering _pypi_hidden'.split()
            args = tuple([info.get(k, None) for k in cols])
            params = ','.join(['%s']*len(cols))
            scols = ','.join(cols)
            sql = 'insert into releases (%s) values (%s)'%(scols, params)
            safe_execute(cursor, sql, args)

            # journal entry
            safe_execute(cursor, '''insert into journals (name, version, action,
                submitted_date, submitted_by, submitted_from) values
                (%s, %s, %s, %s, %s, %s)''', (name, version, 'new release',
                date, self.username, self.userip))

            # first person to add an entry may be considered owner - though
            # make sure they don't already have the Role (this might just
            # be a new version, or someone might have already given them
            # the Role)
            if not self.has_role('Owner', name):
                self.add_role(self.username, 'Owner', name)

            # hide all other releases of this package
            safe_execute(cursor, 'update releases set _pypi_hidden=%s where '
                'name=%s and version <> %s', ('TRUE', name, version))

        # add description urls
        if html:
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
        for col in ('requires', 'provides', 'obsoletes'):
            if not info.has_key(col) or relationships.get(col, []) == info[col]:
                continue
            safe_execute(cursor, '''delete from release_%s where name=%%s
                and version=%%s'''%col, (name, version))
            for specifier in info[col]:
                safe_execute(cursor, '''insert into release_%s (name, version,
                    specifier) values (%%s, %%s, %%s)'''%col, (name,
                    version, specifier))

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
        l = []
        o = {}
        for version, ordering in cursor.fetchall():
            o[version] = ordering
            l.append(LooseVersion(version))
        if new_version is not None:
            l.append(LooseVersion(new_version))
        l.sort()
        n = len(l)

        # most packages won't need to renumber if we give them 100 releases
        max = 10 ** min(math.ceil(math.log10(n)), 2)

        # figure the ordering values for the releases
        for i in range(n):
            v = l[i].vstring
            order = max+i
            if v == new_version:
                new_version = order
            elif order != o[v]:
                # ordering has changed, update
                safe_execute(cursor, '''update releases set _pypi_ordering=%s
                    where name=%s and version=%s''', (order, name, v))

        # return the ordering for this release
        return new_version

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
        name = normalize_package_name(name)
        sql = 'select name from packages where normalized_name=%s'
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

    _Package = FastResultRow('''name stable_version version author author_email
            maintainer maintainer_email home_page license summary description
            description_html keywords platform download_url _pypi_ordering!
            _pypi_hidden! cheesecake_installability_id!
            cheesecake_documentation_id! cheesecake_code_kwalitee_id!''')
    def get_package(self, name, version):
        ''' Retrieve info about the package from the database.

            Returns a mapping with the package info.
        '''
        cursor = self.get_cursor()
        sql = '''select packages.name as name, stable_version, version, author,
                  author_email, maintainer, maintainer_email, home_page,
                  license, summary, description, description_html, keywords,
                  platform, download_url, _pypi_ordering, _pypi_hidden,
                  cheesecake_installability_id,
                  cheesecake_documentation_id,
                  cheesecake_code_kwalitee_id
                 from packages, releases
                 where packages.name=%s and version=%s
                  and packages.name = releases.name'''
        safe_execute(cursor, sql, (name, version))
        return self._Package(None, cursor.fetchone())

    def get_package_urls(self, name):
        ''' Return all URLS (home, download, files) for a package,

            Return pairs of (link, rel, label).
        '''
        cursor = self.get_cursor()
        result = []

        # homepage, download url
        safe_execute(cursor, '''select version, home_page, download_url from
        releases where name=%s''', (name,))
        any_releases = False
        for version, home_page, download_url in cursor.fetchall():
            any_releases = True
            if home_page and home_page != 'UNKNOWN':
                result.append((home_page, 'homepage', version + ' home_page'))
            if download_url and download_url != 'UNKNOWN':
                result.append((download_url, 'download', version + ' download_url'))
        if not any_releases:
            return None

        # uploaded files
        safe_execute(cursor, '''select filename, python_version, md5_digest from release_files
        where name=%s''', (name,))
        for fname, pyversion, md5 in cursor.fetchall():
            result.append((self.gen_file_url(pyversion, name, fname)+"#md5="+md5,
                           None, fname))

        # urls from description
        safe_execute(cursor, '''select distinct url from description_urls
        where name=%s''', (name,))
        for url, in cursor.fetchall():
            result.append((url, None, url))

        return result

    def get_stable_version(self, name):
        ''' Retrieve the version marked as a package:s stable version.
        '''
        cursor = self.get_cursor()
        sql = 'select stable_version from packages where name=%s'
        safe_execute(cursor, sql, (name, ))
        return cursor.fetchone()[0]

    _Packages = FastResultRow('name stable_version')
    def get_packages(self):
        ''' Fetch the complete list of packages from the database.
        '''
        cursor = self.get_cursor()
        safe_execute(cursor, 'select name,stable_version from packages order by name')
        return Result(None, cursor.fetchall(), self._Packages)

    _Journal = FastResultRow('action submitted_date! submitted_by submitted_from')
    def get_journal(self, name, version):
        ''' Retrieve info about the package from the database.

            Returns a list of the journal entries, giving those entries
            specific to the nominated version and those entries not specific
            to any version.
        '''
        cursor = self.get_cursor()
        # get the generic stuff or the stuff specific to the version
        sql = '''select action, submitted_date, submitted_by, submitted_from
            from journals where name=%s and (version=%s or
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
            if spec['_pypi_hidden'] in ('1', 1): v = 'TRUE'
            else: v = 'FALSE'
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

    _Classifiers = FastResultRow('classifier')
    def get_classifiers(self):
        ''' Fetch the list of valid classifiers from the database.
        '''
        cursor = self.get_cursor()
        safe_execute(cursor, 'select classifier from trove_classifiers'
            ' order by classifier')
        return Result(None, cursor.fetchall(), self._Classifiers)

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
        safe_execute(cursor, '''select specifier from release_%s where
            name=%%s and version=%%s'''%relationship, (name, version))
        return Result(None, cursor.fetchall(), self._Release_Relationships)

    _Package_Roles = FastResultRow('role_name user_name')
    def get_package_roles(self, name):
        ''' Fetch the list of Roles for the package.
        '''
        cursor = self.get_cursor()
        safe_execute(cursor, '''select role_name, user_name
            from roles where package_name=%s''', (name, ))
        return Result(None, cursor.fetchall(), self._Package_Roles)

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
                  and r._pypi_hidden = FALSE
                  and j.submitted_date > %s
            order by submitted_date desc
        ''', (time.strftime('%Y-%m-%d %H:%M:%S +0000', time.gmtime(since)),))

        return Result(None, self.get_unique(cursor.fetchall()),
                self._Updated_Releases)

    _Changelog = FastResultRow('name version submitted_date! action')
    def changelog(self, since):
        '''Fetch (name, version, submitted_date, action) since 'since' argument.
        '''

        assert isinstance(since, int)

        cursor = self.get_cursor()
        safe_execute(cursor, '''
            select name,version,submitted_date,action
            from journals j
            where j.submitted_date > %s
        ''', (time.strftime('%Y-%m-%d %H:%M:%S +0000', time.gmtime(since)),))

        return Result(None, cursor.fetchall(), self._Changelog)

    _Latest_Releases = FastResultRow('name version submitted_date! summary')
    def latest_releases(self, num=40):
        ''' Fetch "number" latest releases, youngest to oldest.
        '''
        cursor = self.get_cursor()
        # After the limited query below, we still have to do
        # filtering. Assume that doubling the number of records
        # we look for will still allow for sufficient room for
        # filtering out unneeded records. If this was wrong,
        # try again without limit.
        limit = ' limit %s' % (2*num)
        # This query is designed to run from the journals_latest_releases
        # index, doing a reverse index scan, then lookups in the releases
        # table to find the description and whether the package is hidden.
        # Postgres will only do that if the number of expected results
        # is "small".
        statement = '''
             select j.name, j.version, j.submitted_date, r.summary
             from (select name,version,submitted_date from journals
             where version is not null and action='new release'
             order by submitted_date desc %s) j, releases r
             where  j.name=r.name and j.version=r.version
             and not r._pypi_hidden order by j.submitted_date desc'''
        #print ' '.join((statement % limit).split())
        safe_execute(cursor, statement % limit)
        result = Result(None, self.get_unique(cursor.fetchall())[:num],
                self._Latest_Releases)
        if len(result) == num:
            return result
        # try again without limit
        safe_execute(cursor, statement % '')
        return Result(None, self.get_unique(cursor.fetchall())[:num],
                self._Latest_Releases)

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
                  and r._pypi_hidden = FALSE
            order by submitted_date desc
        ''')

        return Result(None, self.get_unique(cursor.fetchall())[:num],
                self._Latest_Updates)

    _Latest_Release = FastResultRow('''name version submitted_date! summary
            _pypi_hidden!''')
    def get_latest_release(self, name, hidden=None):
        ''' Fetch all releses for the package name, including hidden.
        '''
        args = [name, name]
        if hidden is not None:
            args.append(hidden)
            hidden = 'and _pypi_hidden = %s'
        else:
            hidden = ''
        cursor = self.get_cursor()
        safe_execute(cursor, '''
            select r.name as name,r.version as version,j.submitted_date,
                r.summary as summary,_pypi_hidden
            from journals j, releases r
            where j.version is not NULL
                  and j.action = 'new release'
                  and j.name = %%s
                  and r.name = %%s
                  and j.version = r.version
                  %s
            order by submitted_date desc
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

    def updateurls(self):
        cursor = self.get_cursor()
        safe_execute(cursor, '''select name, version, description_html from
                releases where description_html is not null''')
        for name, version, desc in cursor.fetchall():
            urls = get_description_urls(desc)
            self.update_description_urls(name, version, urls)

    def update_normalized_text(self):
        cursor = self.get_cursor()
        safe_execute(cursor, 'select name from packages')
        for name, in cursor.fetchall():
            safe_execute(cursor, 'update packages set normalized_name=%s where name=%s',
                         [normalize_package_name(name), name])

    def remove_release(self, name, version):
        ''' Delete a single release from the database.
        '''
        cursor = self.get_cursor()

        # delete the files
        for file in self.list_files(name, version):
            os.remove(self.gen_file_path(file['python_version'], name,
                file['filename']))

        # delete ancillary table entries
        for tab in ('files', 'provides', 'requires', 'obsoletes',
                'classifiers'):
            safe_execute(cursor, '''delete from release_%s where
                name=%%s and version=%%s'''%tab, (name, version))
        safe_execute(cursor, 'delete from description_urls where name=%s and version=%s',
               (name, version))

        # delete releases table entry
        safe_execute(cursor, 'delete from releases where name=%s and version=%s',
            (name, version))

    def remove_package(self, name):
        ''' Delete an entire package from the database.
        '''
        cursor = self.get_cursor()
        for release in self.get_package_releases(name):
            for file in self.list_files(name, release['version']):
                os.remove(self.gen_file_path(file['python_version'], name,
                    file['filename']))

        # delete ancillary table entries
        for tab in ('files', 'provides', 'requires', 'obsoletes',
                'classifiers'):
            safe_execute(cursor, 'delete from release_%s where name=%%s'%tab,
                (name, ))

        safe_execute(cursor, 'delete from description_urls where name=%s', (name,))
        safe_execute(cursor, 'delete from releases where name=%s', (name,))
        safe_execute(cursor, 'delete from journals where name=%s', (name,))
        safe_execute(cursor, 'delete from roles where package_name=%s', (name,))
        safe_execute(cursor, 'delete from packages where name=%s', (name,))

    def rename_package(self, old, new):
        ''' Rename a package. Relies on cascaded updates.
        '''
        cursor = self.get_cursor()
        date = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())
        safe_execute(cursor, '''update packages
        set name=%s, normalized_name=%s where name=%s''',
                     (new, normalize_package_name(new), old))
        safe_execute(cursor, '''update journals set name=%s where name=%s''',
                     (new, old))
        # move all files on disk
        sql = '''select python_version, filename
            from release_files where name=%s'''
        safe_execute(cursor, sql, (new,))
        for pyversion, filename in cursor.fetchall():
            oldname = self.gen_file_path(pyversion, old, filename)
            newname = self.gen_file_path(pyversion, new, filename)
            if not os.path.exists(oldname):
                continue
            dirpath = os.path.split(newname)[0]
            if not os.path.exists(dirpath):
                os.makedirs(dirpath)
            os.rename(oldname, newname)
        safe_execute(cursor,'''insert into journals (name, version, action,
                submitted_date, submitted_by, submitted_from) values
                (%s, %s, %s, %s, %s, %s)''', (new,
                                              None,
                                              'rename from %s' % old,
                                              date,
                                              self.username,
                                              self.userip))

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


    #
    # Users interface
    #
    def has_user(self, name):
        ''' Determine whether the user exists in the database.

            Returns true/false.
        '''
        cursor = self.get_cursor()
        safe_execute(cursor, "select count(*) from users where name=%s",
            (name, ))
        return int(cursor.fetchone()[0])

    def store_user(self, name, password, email, gpg_keyid):
        ''' Store info about the user to the database.

            The "password" argument is passed in cleartext and sha-ed
            before storage.

            New user entries create a rego_otk entry too and return the OTK.
        '''
        cursor = self.get_cursor()
        if self.has_user(name):
            if password:
                # update existing user, including password
                password = sha.sha(password).hexdigest()
                safe_execute(cursor,
                   'update users set password=%s, email=%s where name=%s',
                    (password, email, name))
            else:
                # update existing user - but not password
                safe_execute(cursor, 'update users set email=%s where name=%s',
                    (email, name))
            if gpg_keyid is not None:
                safe_execute(cursor, 'update users set gpg_keyid=%s where name=%s',
                    (gpg_keyid, name))
            return None

        password = sha.sha(password).hexdigest()

        # new user
        safe_execute(cursor,
           'insert into users (name, password, email) values (%s, %s, %s)',
           (name, password, email))
        otk = ''.join([random.choice(chars) for x in range(32)])
        safe_execute(cursor, 'insert into rego_otk (name, otk) values (%s, %s)',
            (name, otk))
        return otk

    _User = FastResultRow('name password email gpg_keyid last_login!')
    def get_user(self, name):
        ''' Retrieve info about the user from the database.

            Returns a mapping with the user info or None if there is no
            such user.
        '''
        cursor = self.get_cursor()
        safe_execute(cursor, '''select name, password, email, gpg_keyid, last_login
            from users where name=%s''', (name,))
        return self._User(None, cursor.fetchone())

    def get_user_by_email(self, email):
        ''' Retrieve info about the user from the database, looked up by
            email address.

            Returns a mapping with the user info or None if there is no
            such user.
        '''
        cursor = self.get_cursor()
        safe_execute(cursor, '''select name, password, email, gpg_keyid
            from users where email=%s''', (email,))
        return self._User(None, cursor.fetchone())

    _Users = FastResultRow('name email')
    def get_users(self):
        ''' Fetch the complete list of users from the database.
        '''
        cursor = self.get_cursor()
        safe_execute(cursor, 'select name,email from users order by lower(name)')
        return Result(None, cursor.fetchall(), self._Users)

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
        sql = '''insert into journals (
              name, version, action, submitted_date, submitted_by,
              submitted_from) values (%s, NULL, %s, %s, %s, %s)'''
        safe_execute(cursor, sql, (package_name, 'add %s %s'%(role_name,
            user_name), date, self.username, self.userip))

    def delete_role(self, user_name, role_name, package_name):
        ''' Delete a role for the user for the package.
        '''
        cursor = self.get_cursor()
        safe_execute(cursor, '''
            delete from roles where user_name=%s and role_name=%s
            and package_name=%s''', (user_name, role_name, package_name))
        date = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())
        safe_execute(cursor, '''insert into journals (
              name, version, action, submitted_date, submitted_by,
              submitted_from) values (%s, NULL, %s, %s, %s, %s)''',
            (package_name, 'remove %s %s'%(role_name, user_name), date,
            self.username, self.userip))

    def delete_otk(self, otk):
        ''' Delete the One Time Key.
        '''
        safe_execute(self.get_cursor(), "delete from rego_otk where otk=%s",
                     (otk,))

    def get_otk(self, name):
        ''' Retrieve the One Time Key for the user.
        '''
        cursor = self.get_cursor()
        safe_execute(cursor, "select otk from rego_otk where name=%s", (name, ))
        res = cursor.fetchone()
        if res is None:
            return ''
        return res[0]

    _User_Packages = FastResultRow('package_name')
    def user_packages(self, user):
        ''' Retrieve package info for all packages of a user
        '''
        cursor = self.get_cursor()
        sql = '''select distinct(package_name),lower(package_name) from roles
                 where roles.user_name=%s and package_name is not NULL
                 order by lower(package_name)'''
        safe_execute(cursor, sql, (user,))
        res = cursor.fetchall()
        if res is None:
            res = []
        return Result(None, res, self._User_Packages)

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
        import time
        cursor = self.get_cursor()
        t = self.trove()
        cursor.execute("select value from timestamps where name='browse_tally'")
        date = cursor.fetchone()[0]
        if time.time() - date.ticks() > 10*60:
            # Regenerate tally. First, release locks we hold on the timestamps
            self._conn.commit()
            # Clear old tally
            cursor.execute("lock table browse_tally")
            cursor.execute("delete from browse_tally")
            # Regenerate tally; see browse() below
            cursor.execute("""insert into browse_tally
            select res.l2, count(*) from (select t.l2, rc.name, rc.version
            from trove_classifiers t, release_classifiers rc, releases r
            where rc.name=r.name and rc.version=r.version and not r._pypi_hidden and rc.trove_id=t.id
            group by t.l2, rc.name, rc.version) res group by res.l2""")
            cursor.execute("update timestamps set value=now() where name='browse_tally'")
            self._conn.commit()
        cursor.execute("select trove_id, tally from browse_tally")
        return [], cursor.fetchall()

    def browse(self, selected_classifiers):
        t = self.trove()
        cursor = self.get_cursor()
        if not selected_classifiers:
            # This is not used; see browse_tally above
            tally = """select res.l2, count(*) from (select t.l2, rc.name, rc.version
            from trove_classifiers t, release_classifiers rc, releases r
            where rc.name=r.name and rc.version=r.version and not r._pypi_hidden and rc.trove_id=t.id
            group by t.l2, rc.name, rc.version) res group by res.l2"""
            cursor.execute(tally)
            return [], cursor.fetchall()

        # First compute statement to produce all packages still selected
        pkgs = "select name, version, summary from releases where _pypi_hidden=FALSE"
        for c in selected_classifiers:
            level = t.trove[c].level
            pkgs = """select distinct a.name, a.version, summary from (%s) a, release_classifiers rc, trove_classifiers t
             where a.name=rc.name and a.version=rc.version and rc.trove_id=t.id and
             t.l%d=%d""" % (pkgs, level, c)
        # Next download all selected releases
        cursor.execute(pkgs)
        releases = []
        for name, version, summary in cursor.fetchall():
            releases.append((name.decode('utf-8'), version, summary.decode('utf-8')))
        # Finally, compute the tally
        tally = """select tl.id,count(*) from (select distinct t.id, a.name,
        a.version from (%s) a, release_classifiers rc, trove_classifiers t, trove_classifiers t2
        where a.name=rc.name and a.version=rc.version and rc.trove_id=t2.id""" % pkgs
        # tally all level-2 classifiers
        tally += " and (t.id=t2.l2"
        # then tally for all level n+1 classifiers of selected_classifiers
        for c in selected_classifiers:
            level = t.trove[c].level
            if level==5:
                # There are no level 6 classifiers
                continue
            tally += " or (t.id=t2.l%d and t2.l%d=%s)" % (level+1, level, c)
        tally += ")) tl group by tl.id"
        cursor.execute(tally)
        tally = cursor.fetchall()
        return releases, tally

    #
    # File handling
    #
    def gen_file_url(self, pyversion, name, filename):
        '''Generate the URL for a given file download.'''
        return os.path.join(self.config.files_url, pyversion,
            name[0], name, filename)

    def gen_file_path(self, pyversion, name, filename):
        '''Generate the path to the file on disk.'''
        return os.path.join(self.config.database_files_dir, pyversion,
            name[0], name, filename)

    def add_file(self, name, version, content, md5_digest, filetype,
            pyversion, comment, filename, signature):
        '''Add to the database and store the content to disk.'''
        # add database entry
        cursor = self.get_cursor()
        sql = '''insert into release_files (name, version, python_version,
            packagetype, comment_text, filename, md5_digest) values
            (%s, %s, %s, %s, %s, %s, %s)'''
        safe_execute(cursor, sql, (name, version, pyversion, filetype,
            comment, filename, md5_digest))

        # store file to disk
        filepath = self.gen_file_path(pyversion, name, filename)
        dirpath = os.path.split(filepath)[0]
        if not os.path.exists(dirpath):
            os.makedirs(dirpath)
        f = open(filepath, 'wb')
        try:
            f.write(content)
        finally:
            f.close()

        # Store signature next to the file
        if signature:
            f = open(filepath + ".asc", "wb")
            try:
                f.write(signature)
            finally:
                f.close()

        # add journal entry
        date = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())
        safe_execute(cursor, '''insert into journals (
              name, version, action, submitted_date, submitted_by,
              submitted_from) values (%s, %s, %s, %s, %s, %s)''',
            (name, version, 'add %s file %s'%(pyversion, filename), date,
            self.username, self.userip))

    _List_Files = FastResultRow('''packagetype python_version comment_text
    filename md5_digest size! has_sig! downloads!''')
    def list_files(self, name, version):
        cursor = self.get_cursor()
        sql = '''select packagetype, python_version, comment_text,
            filename, md5_digest, downloads from release_files
            where name=%s and version=%s'''
        safe_execute(cursor, sql, (name, version))
        l = []
        for pt, pv, ct, fn, m5, dn in cursor.fetchall():
            path = self.gen_file_path(pv, name, fn)
            try:
                size = os.stat(path)[stat.ST_SIZE]
            except OSError, error:
                if error.errno != errno.ENOENT: raise
                # file not on disk any more - don't list it
                continue
            has_sig = os.path.exists(path+'.asc')
            l.append(self._List_Files(None, (pt, pv, ct, fn, m5, size, has_sig, dn)))
        return l

    def has_file(self, name, version, filename):
        cursor = self.get_cursor()
        sql = '''select count(*) from release_files
            where name=%s and version=%s and filename=%s'''
        safe_execute(cursor, sql, (name, version, filename))
        return int(cursor.fetchone()[0])

    def remove_file(self, digest):
        cursor = self.get_cursor()
        sql = '''select python_version, name, filename from release_files
            where md5_digest=%s'''
        safe_execute(cursor, sql, (digest, ))
        info = cursor.fetchone()
        if not info:
            raise KeyError, 'no such file'
        pyversion, name, filename = info
        safe_execute(cursor, 'delete from release_files where md5_digest=%s',
            (digest, ))
        filepath = self.gen_file_path(pyversion, name, filename)
        dirpath = os.path.split(filepath)[0]
        os.remove(filepath)
        if os.path.exists(filepath+'.asc'):
            os.remove(filepath+'.asc')
        while True:
            if os.listdir(dirpath):
                break
            if dirpath == self.config.database_files_dir:
                break
            os.rmdir(dirpath)
            dirpath = os.path.split(dirpath)[0]

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

    def log_docs(self, name, version):
        cursor = self.get_cursor()
        date = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())
        safe_execute(cursor, '''insert into journals (name, version, action,
            submitted_date, submitted_by, submitted_from) values
                (%s, %s, %s, %s, %s, %s)''', (name,
                                              version,
                                              'docupdate',
                                              date,
                                              self.username,
                                              self.userip))


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
        cd = dict(database=self.config.database_name, user=self.config.database_user)
        if self.config.database_pw:
            cd['password'] = self.config.database_pw
        if keep_conn and connection:
            self._conn = connection
            # Rollback any uncommitted earlier change
            try:
                self._conn.rollback()
            except psycopg.InterfaceError, e:
                # already closed
                connection = None
                return self.open()
        else:
            self._conn = connection = psycopg.connect(**cd)

        cursor = self._cursor = self._conn.cursor()

    def set_user(self, username, userip, update_last_login):
        ''' Set the user who is doing the changes.
        '''
        # now check the user
        if username is not None:
            if self.has_user(username):
                self.username = username
                if update_last_login:
                    self.get_cursor().execute('''
                    update users set last_login=now() where name=%s''', (username,))
        self.userip = userip

    def setpasswd(self, username, password):
        password = sha.sha(password).hexdigest()
        self.get_cursor().execute('''
            update users set password=%s where name=%s
            ''', (password, username))

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

    def rollback(self):
        if self._conn is None:
            return
        self._conn.rollback()
        self._cursor = None

def processDescription(source, output_encoding='unicode'):
    """Given an source string, returns an HTML fragment as a string.

    The return value is the contents of the <body> tag.

    Parameters:

    - `source`: A multi-line text string; required.
    - `output_encoding`: The desired encoding of the output.  If a Unicode
      string is desired, use the default value of "unicode" .
    """
    from docutils.core import publish_parts
    from docutils.readers.python.moduleparser import trim_docstring
    # Dedent all lines of `source`.
    source = trim_docstring(source)

    settings_overrides={
        'raw_enabled': '0',  # no raw HTML code
        'file_insertion_enabled': '0',  # no file/URL access
        'halt_level': 2,  # at warnings or errors, raise an exception
        'report_level': 5,  # never report problems with the reST code
        }

    # capture publishing errors, they go to stderr
    old_stderr = sys.stderr
    sys.stderr = s = cStringIO.StringIO()
    parts = None
    try:
        # Convert reStructuredText to HTML using Docutils.
        parts = publish_parts(source=source, writer_name='html',
                              settings_overrides=settings_overrides)
    except:
        pass

    sys.stderr = old_stderr

    # original text if publishing errors occur
    if parts is None or len(s.getvalue()) > 0:
        output = "".join('<PRE>\n' + source + '</PRE>')
    else:
        output = parts['body']

    if output_encoding != 'unicode':
        output = output.encode(output_encoding)

    return output

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
            result.append(url)
    return result

if __name__ == '__main__':
    import config
    cfg = config.Config(sys.argv[1], 'webui')
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
    elif sys.argv[2] == 'updateurls':
        store.updateurls()
        store.commit()
    elif sys.argv[2] == 'update_normalized_text':
        store.update_normalized_text()
        store.commit()
    else:
        print "UNKNOWN COMMAND", sys.argv[2]
    store.close()

