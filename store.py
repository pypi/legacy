''' Implements a store of disutils PKG-INFO entries, keyed off name, version.
'''
import sys, os, re, sqlite, time, sha, whrandom

chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'

class StorageError(Exception):
    pass

class Store:
    ''' Store info about packages, and allow query and retrieval.

        Packages are unique by (name, version).

        Other package info, as defined by distutils:
          name
          version
          author
          author_email
          maintainer
          maintainer_email
          home_page
          license
          summary
          description
          long_description
          keywords
          platform

        Additional info:
          download_url
          hidden

        Trove metadata storage:
          name
          version
          category_id

        Trove categories:
          id
          text

        Package journal:
          name
          version
          action
          submitted_date
          submitted_by
          submitted_from

        Users table:
          username
          password
          email
          public_key

        Roles table:
          user_name
          role_name          (Admin, Owner or Maintainer)
          package_name

        Additional support for registration:
          rego_otk (
            name             (user)
            otk
          )
    '''
    def __init__(self, config):
        self.config = config
        self.username = None
        self.userip = None

    def store_package(self, name, version, info):
        ''' Store info about the package to the database.

            We automatically set the "submitted_date" column here, don't
            send it in.
        '''
        # make sure the user is identified
        if not self.username:
            raise StorageError, \
                "You must be identified to store package information"

        date = time.strftime('%Y-%m-%d %H:%M:%S')
        cols = info.keys()
        if self.has_package(name, version):
            # make sure the user has permission to do stuff
            if not (self.has_role('Maintainer', name) or
                    self.has_role('Owner', name)):
                raise StorageError, \
                    "You are not allowed to store '%s' package information"%name
            # update
            args = [info[k] for k in cols]
            info = ','.join(['%s=%%s'%x for x in cols])
            sql = "update packages set %s where name='%s' and version='%s'"%(
                info, name, version)
            self.cursor.execute(sql, args)
            self.cursor.execute('''insert into journal (
                  name, version, action, submitted_date, submitted_by,
                  submitted_from) values (%s, %s, %s, %s, %s, %s)''',
                (name, version, 'update', date, self.username, self.userip))
        else:
            # insert
            info['name'] = name
            info['version'] = version
            args = [info[k] for k in cols]
            cols = ','.join(cols)
            params = ','.join(['%s']*len(info))
            sql = 'insert into packages (%s) values (%s)'%(cols, params)
            self.cursor.execute(sql, args)

            # journal entry
            self.cursor.execute('''insert into journal (
                  name, version, action, submitted_date, submitted_by,
                  submitted_from) values (%s, %s, %s, %s, %s, %s)''',
                (name, version, 'create', date, self.username, self.userip))

            # first person to add an entry may be considered owner
            self.add_role(self.username, 'Owner', name)

    def has_package(self, name, version):
        ''' Determine whether the package exists in the database.

            Returns true/false.
        '''
        self.cursor.execute("select count(*) from packages where name='%s' "
            " and version='%s'"%(name, version))
        res = int(self.cursor.fetchone()[0])
        return res

    def get_package(self, name, version):
        ''' Retrieve info about the package from the database.

            Returns a mapping with the package info.
        '''
        self.cursor.execute("select * from packages where name='%s' "
            " and version='%s'"%(name, version))
        return self.cursor.fetchone()

    def get_journal(self, name, version):
        ''' Retrieve info about the package from the database.

            Returns a mapping with the package info.
        '''
        self.cursor.execute("select * from journal where name=%s "
            " and (version=%s or version is NULL)", (name, version))
        return self.cursor.fetchall()

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
        sql = 'select name,version from packages %s'%where
        self.cursor.execute(sql)
        l = self.cursor.fetchall()
        return l

    #
    # Users interface
    # 
    def has_user(self, name):
        ''' Determine whether the user exists in the database.

            Returns true/false.
        '''
        self.cursor.execute("select count(*) from users where name='%s'"%name)
        return int(self.cursor.fetchone()[0])

    def store_user(self, name, password, email):
        ''' Store info about the user to the database.

            The "password" argument is passed in cleartext and sha'ed
            before storage.

            New user entries create a rego_otk entry too and return the OTK.
        '''
        password = sha.sha(password).hexdigest()
        if self.has_user(name):
            # update existing user
            self.cursor.execute(
               'update users set password=%s, email=%s where name=%s',
                (password, email, name))
            return None

        # new user
        self.cursor.execute(
           'insert into users (name, password, email) values (%s, %s, %s)',
           (name, password, email))
        otk = ''.join([whrandom.choice(chars) for x in range(32)])
        self.cursor.execute(
           'insert into rego_otk (name, otk) values (%s, %s)', (name, otk))
        return otk

    def get_user(self, name):
        ''' Retrieve info about the user from the database.

            Returns a mapping with the user info or None if there is no
            such user.
        '''
        self.cursor.execute("select * from users where name=%s", (name,))
        return self.cursor.fetchone()

    def get_user_by_email(self, email):
        ''' Retrieve info about the user from the database, looked up by
            email address.

            Returns a mapping with the user info or None if there is no
            such user.
        '''
        self.cursor.execute("select * from users where email=%s", (email,))
        return self.cursor.fetchone()

    def has_role(self, role_name, package_name, user_name=None):
        ''' Determine whether the current user has the named Role for the
            named package.
        '''
        if user_name is None:
            user_name = self.username
        if user_name is None:
            return 0
        sql = '''select count(*) from roles where user_name=%s and
            role_name=%s and (package_name=%s or package_name is NULL)'''
        self.cursor.execute(sql, (user_name, role_name, package_name))
        return int(self.cursor.fetchone()[0])

    def add_role(self, user_name, role_name, package_name):
        ''' Add a role to the user for the package.
        '''
        self.cursor.execute('''
            insert into roles (user_name, role_name, package_name)
            values (%s, %s, %s)''', (user_name, role_name, package_name))
        date = time.strftime('%Y-%m-%d %H:%M:%S')
        sql = '''insert into journal (
              name, version, action, submitted_date, submitted_by,
              submitted_from) values (%s, NULL, %s, %s, %s, %s)'''
        self.cursor.execute(sql, (package_name, 'add %s %s'%(role_name,
            user_name), date, self.username, self.userip))

    def delete_role(self, user_name, role_name, package_name):
        ''' Delete a role for the user for the package.
        '''
        self.cursor.execute('''
            delete from roles where user_name=%s and role_name=%s
            and package_name=%s''', (user_name, role_name, package_name))
        date = time.strftime('%Y-%m-%d %H:%M:%S')
        self.cursor.execute('''insert into journal (
              name, version, action, submitted_date, submitted_by,
              submitted_from) values (%s, NULL, %s, %s, %s, %s)''',
            (package_name, 'remove %s %s'%(role_name, user_name), date,
            self.username, self.userip))

    def delete_otk(self, otk):
        ''' Delete the One Time Key.
        '''
        self.cursor.execute('delete from rego_otk where otk=%s', (otk,))

    def get_otk(self, name):
        ''' Retrieve the One Time Key for the user.
        '''
        self.cursor.execute("select * from rego_otk where name='%s'"%name)
        res = self.cursor.fetchone()
        if res is None:
            return ''
        return res['otk']

    #
    # Handle the underlying database
    #
    def open(self):
        ''' Open the database, initialising if necessary.
        '''
        # ensure files are group readable and writable
        self.conn = sqlite.connect(db=self.config.database)
        self.cursor = self.conn.cursor()
        try:
            self.cursor.execute('select count(*) from packages')
            self.cursor.fetchone()
        except sqlite.DatabaseError, error:
            if str(error) != 'no such table: packages':
                raise
            self.cursor.execute('''
               create table packages (
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
                  long_description varchar,
                  keywords varchar,
                  platform varchar,
                  download_url varchar,
                  hidden varchar
               )''')
            self.cursor.execute('''
               create table journal (
                  name varchar,
                  version varchar,
                  action varchar,
                  submitted_date varchar,
                  submitted_by varchar,
                  submitted_from varchar
               )''')
            self.cursor.execute('''
               create table users (
                  name varchar,
                  password varchar,
                  email varchar,
                  public_key varchar
               )''')
            self.cursor.execute('''
               create table rego_otk (
                  name varchar,
                  otk varchar
               )''')
            self.cursor.execute('''
               create table roles (
                  user_name varchar,
                  role_name varchar,
                  package_name varchar
               )''')

            # admin user
            adminpw = ''.join([whrandom.choice(chars) for x in range(10)])
            adminpw = sha.sha(adminpw).hexdigest()
            self.cursor.execute('''
               insert into users (name, password, email) values
                ('admin', '%s', NULL)
               '''%adminpw)
            self.cursor.execute('''
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
        self.cursor.execute('''
            update users set password='%s' where name='%s'
            '''%(password, username))

    def close(self):
        try:
            self.conn.close()
        except sqlite.ProgrammingError, value:
            if str(value) != 'close failed - Connection is closed.':
                raise

    def commit(self):
        try:
            self.conn.commit()
        except sqlite.DatabaseError, error:
            if str(error) != 'cannot commit - no transaction is active':
                raise

    def rollback(self):
        # roll back
        try:
            self.conn.rollback()
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
    store.close()

