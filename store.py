''' Implements a store of disutils PKG-INFO entries, keyed off name, version.
'''
import sys, os, re, sqlite, time, sha, whrandom, types, math, stat
from distutils.version import LooseVersion

chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'

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

    def store_package(self, name, version, info):
        ''' Store info about the package to the database.
        '''
        date = time.strftime('%Y-%m-%d %H:%M:%S')

        cursor = self.get_cursor()
        # see if we're inserting or updating a package
        if not self.has_package(name):
            # insert the new package entry
            sql = 'insert into packages (name) values (%s)'
            cursor.execute(sql, (name, ))

            # journal entry
            cursor.execute('''insert into journals (name, version, action,
                submitted_date, submitted_by, submitted_from) values
                (%s, %s, %s, %s, %s, %s)''', (name, None, 'create', date,
                self.username, self.userip))

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
        old_cifiers = []
        if self.has_release(name, version):
            # figure the changes
            existing = self.get_package(name, version)

            # handle the special vars that most likely won't have been
            # submitted
            for k in ('_pypi_ordering', '_pypi_hidden'):
                if not info.has_key(k):
                    info[k] = existing[k]

            old = []
            specials = 'name version'.split()
            for k, v in existing.items():
                if k not in specials and info.get(k, None) != v:
                    if v is None: v = 'NULL'
                    else: v = repr(v)
                    old.append('%s'%k)
            # get old list
            old_cifiers = self.get_release_classifiers(name, version)
            old_cifiers.sort()
            if info.has_key('classifiers') and old_cifiers != classifiers:
                old.append('classifiers')

            # no update when nothing changes
            if not old:
                return None

            # create the journal/user message
            message = 'update %s'%', '.join(old)

            # update
            cols = 'author author_email maintainer maintainer_email home_page license summary description keywords platform download_url _pypi_ordering _pypi_hidden'.split()
            args = tuple([info.get(k, None) for k in cols] + [name, version])
            vals = ','.join(['%s=%%s'%x for x in cols])
            sql = "update releases set %s where name=%%s and version=%%s"%vals
            cursor.execute(sql, args)

            # journal the update
            cursor.execute('''insert into journals (name, version,
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

            # perform the insert
            cols = 'name version author author_email maintainer maintainer_email home_page license summary description keywords platform download_url _pypi_ordering _pypi_hidden'.split()
            args = tuple([info.get(k, None) for k in cols])
            params = ','.join(['%s']*len(cols))
            scols = ','.join(cols)
            sql = 'insert into releases (%s) values (%s)'%(scols, params)
            cursor.execute(sql, args)

            # journal entry
            cursor.execute('''insert into journals (name, version, action,
                submitted_date, submitted_by, submitted_from) values
                (%s, %s, %s, %s, %s, %s)''', (name, version, 'new release',
                date, self.username, self.userip))

            # first person to add an entry may be considered owner - though
            # make sure they don't already have the Role (this might just
            # be a new version, or someone might have already given them
            # the Role)
            if not self.has_role('Owner', name):
                self.add_role(self.username, 'Owner', name)

        # handle trove information
        if not info.has_key('classifiers') or old_cifiers == classifiers:
            return message

        # otherwise save them off
        cursor.execute('delete from release_classifiers where name=%s'
            ' and version=%s', (name, version))
        for classifier in classifiers:
            cursor.execute('select id from trove_classifiers where'
                ' classifier=%s', (classifier, ))
            trove_id = cursor.fetchone()[0]
            cursor.execute('insert into release_classifiers '
                '(name, version, trove_id) values (%s, %s, %s)',
                (name, version, trove_id))
        return message

    def fix_ordering(self, name, new_version=None):
        ''' Fix the _pypi_ordering column for a package's releases.

            If "new_version" is supplied, insert it into the sequence and
            return the ordering value for it.

            XXX Because sqlite only handles strings, we'll need to make
            sure the values are string-sortable.
        '''
        cursor = self.get_cursor()
        # load up all the version strings for this package and sort them
        cursor.execute(
            'select version,_pypi_ordering from releases where name=%s', name)
        l = []
        o = {}
        for release in cursor.fetchall():
            o[release['version']] = release['_pypi_ordering']
            l.append(LooseVersion(release['version']))
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
                cursor.execute('''update releases set _pypi_ordering=%s
                    where name=%s and version=%s''', (order, name, v))

        # return the ordering for this release
        return new_version

    def has_package(self, name):
        ''' Determine whether the package exists in the database.

            Returns true/false.
        '''
        cursor = self.get_cursor()
        sql = 'select count(*) from packages where name=%s'
        cursor.execute(sql, (name, ))
        return int(cursor.fetchone()[0])

    def has_release(self, name, version):
        ''' Determine whether the release exists in the database.

            Returns true/false.
        '''
        cursor = self.get_cursor()
        sql = 'select count(*) from releases where name=%s and version=%s'
        cursor.execute(sql, (name, version))
        return int(cursor.fetchone()[0])

    def get_package(self, name, version):
        ''' Retrieve info about the package from the database.

            Returns a mapping with the package info.
        '''
        cursor = self.get_cursor()
        sql = '''select packages.name as name, stable_version, version, author,
                  author_email, maintainer, maintainer_email, home_page,
                  license, summary, description, keywords,
                  platform, download_url, _pypi_ordering, _pypi_hidden
                 from packages, releases
                 where packages.name=%s and version=%s
                  and packages.name = releases.name'''
        cursor.execute(sql, (name, version))
        return cursor.fetchone()

    def get_packages(self):
        ''' Fetch the complete list of packages from the database.
        '''
        cursor = self.get_cursor()
        cursor.execute('select * from packages')
        return cursor.fetchall()

    def get_journal(self, name, version):
        ''' Retrieve info about the package from the database.

            Returns a list of the journal entries, giving those entries
            specific to the nominated version and those entries not specific
            to any version.
        '''
        cursor = self.get_cursor()
        # get the generic stuff or the stuff specific to the version
        sql = '''select * from journals where name=%s and (version=%s or
                version is NULL) order by submitted_date'''
        cursor.execute(sql, (name, version))
        return cursor.fetchall()

    def query_packages(self, spec, andor='and'):
        ''' Find packages that match the spec.

            Return a list of (name, version) tuples.
        '''
        where = []
        for k, v in spec.items():
            if type(v) != type([]): v = [v]
            # Quote the bits in the string that need it and then embed
            # in a "substring" search. Note - need to quote the '%' so
            # they make it through the python layer happily
            v = ['%%'+s.replace("'", "''")+'%%' for s in v]

            # now add to the where clause
            where.append(' or '.join(["%s LIKE '%s'"%(k, s) for s in v]))

        # construct the SQL
        if where:
            where = ' where ' + ((' %s '%andor).join(where))
        else:
            where = ''

        # do the fetch
        cursor = self.get_cursor()
        sql = '''select name, version, summary from releases %s
            order by lower(name), _pypi_ordering'''%where
        cursor.execute(sql)
        l = cursor.fetchall()
        return l

    def get_classifiers(self):
        ''' Fetch the list of valid classifiers from the database.
        '''
        cursor = self.get_cursor()
        cursor.execute('select classifier from trove_classifiers'
            ' order by classifier')
        return [x[0] for x in cursor.fetchall()]

    def get_release_classifiers(self, name, version):
        ''' Fetch the list of classifiers for the release.
        '''
        cursor = self.get_cursor()
        cursor.execute('''select classifier
            from trove_classifiers, release_classifiers where id=trove_id
            and name=%s and version=%s order by classifier''', (name, version))
        return [x[0] for x in cursor.fetchall()]

    def get_package_roles(self, name):
        ''' Fetch the list of Roles for the package.
        '''
        cursor = self.get_cursor()
        cursor.execute('''select role_name, user_name
            from roles where package_name=%s''', (name, ))
        return cursor.fetchall()

    def latest_updates(self, num=20):
        ''' Fetch "number" latest updates, youngest to oldest.
        '''
        cursor = self.get_cursor()
        cursor.execute('''
            select j.name,j.version,j.submitted_date,r.summary
            from journals j, releases r
            where j.version is not NULL
                  and j.name = r.name and j.version = r.version
                  and r._pypi_hidden == 0
            order by submitted_date desc
        ''')
        d = {}
        l = []
        for name,version,date,summary in cursor.fetchall():
            k = (name,version)
            if d.has_key(k):
                continue
            l.append((name,version,date,summary))
            d[k] = 1   
        return l[:num]

    def get_package_releases(self, name):
        ''' Fetch all releses for the package name, including hidden.
        '''
        cursor = self.get_cursor()
        cursor.execute('select * from releases where name=%s', name)
        res = cursor.fetchall()
        if res is None:
            return []
        return res

    def remove_release(self, name, version):
        ''' Delete a single release from the database.
        '''
        cursor = self.get_cursor()
        cursor.execute('delete from releases where name=%s and version=%s',
            (name, version))
        cursor.execute('delete from release_classifiers where '
            'name=%s and version=%s', (name, version))

    def remove_package(self, name):
        ''' Delete an entire package from the database.
        '''
        cursor = self.get_cursor()
        cursor.execute('delete from packages where name=%s', name)
        cursor.execute('delete from releases where name=%s', name)
        cursor.execute('delete from release_classifiers where name=%s', name)
        cursor.execute('delete from journals where name=%s', name)
        cursor.execute('delete from roles where package_name=%s', name)


    #
    # Users interface
    # 
    def has_user(self, name):
        ''' Determine whether the user exists in the database.

            Returns true/false.
        '''
        cursor = self.get_cursor()
        cursor.execute("select count(*) from users where name='%s'"%name)
        return int(cursor.fetchone()[0])

    def store_user(self, name, password, email):
        ''' Store info about the user to the database.

            The "password" argument is passed in cleartext and sha'ed
            before storage.

            New user entries create a rego_otk entry too and return the OTK.
        '''
        cursor = self.get_cursor()
        if self.has_user(name):
            if password:
                # update existing user, including password
                password = sha.sha(password).hexdigest()
                cursor.execute(
                   'update users set password=%s, email=%s where name=%s',
                    (password, email, name))
            else:
                # update existing user - but not password
                cursor.execute('update users set email=%s where name=%s',
                    (email, name))
            return None

        password = sha.sha(password).hexdigest()

        # new user
        cursor.execute(
           'insert into users (name, password, email) values (%s, %s, %s)',
           (name, password, email))
        otk = ''.join([whrandom.choice(chars) for x in range(32)])
        cursor.execute('insert into rego_otk (name, otk) values (%s, %s)',
            (name, otk))
        return otk

    def get_user(self, name):
        ''' Retrieve info about the user from the database.

            Returns a mapping with the user info or None if there is no
            such user.
        '''
        cursor = self.get_cursor()
        cursor.execute("select * from users where name=%s", (name,))
        return cursor.fetchone()

    def get_user_by_email(self, email):
        ''' Retrieve info about the user from the database, looked up by
            email address.

            Returns a mapping with the user info or None if there is no
            such user.
        '''
        cursor = self.get_cursor()
        cursor.execute("select * from users where email=%s", (email,))
        return cursor.fetchone()

    def get_users(self):
        ''' Fetch the complete list of users from the database.
        '''
        cursor = self.get_cursor()
        cursor.execute('select name,email from users order by lower(name)')
        return cursor.fetchall()

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
        cursor.execute(sql, (user_name, role_name, package_name))
        return int(cursor.fetchone()[0])

    def add_role(self, user_name, role_name, package_name):
        ''' Add a role to the user for the package.
        '''
        cursor = self.get_cursor()
        cursor.execute('''
            insert into roles (user_name, role_name, package_name)
            values (%s, %s, %s)''', (user_name, role_name, package_name))
        date = time.strftime('%Y-%m-%d %H:%M:%S')
        sql = '''insert into journals (
              name, version, action, submitted_date, submitted_by,
              submitted_from) values (%s, NULL, %s, %s, %s, %s)'''
        cursor.execute(sql, (package_name, 'add %s %s'%(role_name,
            user_name), date, self.username, self.userip))

    def delete_role(self, user_name, role_name, package_name):
        ''' Delete a role for the user for the package.
        '''
        cursor = self.get_cursor()
        cursor.execute('''
            delete from roles where user_name=%s and role_name=%s
            and package_name=%s''', (user_name, role_name, package_name))
        date = time.strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute('''insert into journals (
              name, version, action, submitted_date, submitted_by,
              submitted_from) values (%s, NULL, %s, %s, %s, %s)''',
            (package_name, 'remove %s %s'%(role_name, user_name), date,
            self.username, self.userip))

    def delete_otk(self, otk):
        ''' Delete the One Time Key.
        '''
        self.get_cursor().execute('delete from rego_otk where otk=%s', (otk,))

    def get_otk(self, name):
        ''' Retrieve the One Time Key for the user.
        '''
        cursor = self.get_cursor()
        cursor.execute("select * from rego_otk where name='%s'"%name)
        res = cursor.fetchone()
        if res is None:
            return ''
        return res['otk']

    def user_packages(self, user):
        ''' Retrieve package info for all packages of a user
        '''
        cursor = self.get_cursor()
        sql = '''select distinct(package_name) from roles
                 where roles.user_name=%s and package_name is not NULL
                 order by lower(package_name)'''
        cursor.execute(sql, (user,))
        res = cursor.fetchall()
        if res is None:
            return []
        return res

    #
    # Handle the underlying database
    #
    def last_modified(self):
        return os.stat(self.config.database)[stat.ST_MTIME]

    def get_cursor(self):
        if self._cursor is None:
            self.open()
        return self._cursor

    def open(self):
        ''' Open the database, initialising if necessary.
        '''
        # ensure files are group readable and writable
        self._conn = sqlite.connect(db=self.config.database)

        # set a 30 second timeout (extraordinarily generous) for handling
        # locked database
        self._conn.db.sqlite_busy_timeout(30 * 1000)

        cursor = self._cursor = self._conn.cursor()
        try:
            cursor.execute('select count(*) from ids')
            cursor.fetchone()
        except sqlite.DatabaseError, error:
            if str(error) != 'no such table: ids':
                raise
            cursor.execute('''
               create table ids (
                  name varchar,
                  num varchar
               )''')
            cursor.execute('''
               create table packages (
                  name varchar,
                  stable_version varchar
               )''')
            cursor.execute('''
               create table releases (
                  name varchar,
                  version varchar,
                  author varchar,
                  author_email varchar,
                  maintainer varchar,
                  maintainer_email varchar,
                  home_page varchar,
                  license varchar,
                  summary varchar,
                  description varchar,
                  keywords varchar,
                  platform varchar,
                  download_url varchar,
                  _pypi_ordering varchar,
                  _pypi_hidden varchar
               )''')
            cursor.execute('''
               create table trove_classifiers (
                  id varchar,
                  classifier varchar
               )''')
            cursor.execute('''
               create table release_classifiers (
                  name varchar,
                  version varchar,
                  trove_id varchar
               )''')
            cursor.execute('''
               create table journals (
                  name varchar,
                  version varchar,
                  action varchar,
                  submitted_date varchar,
                  submitted_by varchar,
                  submitted_from varchar
               )''')
            cursor.execute('''
               create table users (
                  name varchar,
                  password varchar,
                  email varchar,
                  public_key varchar
               )''')
            cursor.execute('''
               create table rego_otk (
                  name varchar,
                  otk varchar
               )''')
            cursor.execute('''
               create table roles (
                  role_name varchar,
                  user_name varchar,
                  package_name varchar
               )''')

            # init the id counter
            cursor.execute('''insert into ids (name, num) values
                ('trove_classifier', 1)''')

            # admin user
            adminpw = ''.join([whrandom.choice(chars) for x in range(10)])
            adminpw = sha.sha(adminpw).hexdigest()
            cursor.execute('''
               insert into users (name, password, email) values
                ('admin', '%s', NULL)
               '''%adminpw)
            cursor.execute('''
               insert into roles (user_name, role_name, package_name) values
                ('admin', 'Admin', NULL)
               ''')

    def set_user(self, username, userip):
        ''' Set the user who's doing the changes.
        '''
        # now check the user
        if username is not None:
            if self.has_user(username):
                self.username = username
        self.userip = userip

    def setpasswd(self, username, password):
        password = sha.sha(password).hexdigest()
        self.get_cursor().execute('''
            update users set password='%s' where name='%s'
            '''%(password, username))

    def close(self):
        if self._conn is None:
            return
        try:
            self._conn.close()
            self._conn = None
        except sqlite.ProgrammingError, value:
            if str(value) != 'close failed - Connection is closed.':
                raise

    def commit(self):
        if self._conn is None:
            return
        try:
            self._conn.commit()
        except sqlite.DatabaseError, error:
            if str(error) != 'cannot commit - no transaction is active':
                raise

    def rollback(self):
        if self._conn is None:
            return
        try:
            self._conn.rollback()
        except sqlite.ProgrammingError, value:
            if str(value) != 'rollback failed - Connection is closed.':
                raise

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
    else:
        print "UNKNOWN COMMAND", sys.argv[2]
    store.close()

