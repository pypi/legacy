
import sys, os, urllib, StringIO, traceback, cgi, binascii, getopt, shutil
import zipfile, gzip, tarfile
#sys.path.append('/usr/local/pypi/lib')

import store, config

def set_password(store, name, pw):
    """ Reset the user's password and send an email to the address given.
    """
    user = store.get_user(name.strip())
    if user is None:
        raise ValueError, 'user name unknown to me'
    store.store_user(user['name'], pw.strip(), user['email'], None)
    print 'done'

def remove_spam(store, namepat, confirm=False):
    '''Remove packages that match namepat (SQL wildcards).

    The packages will be removed. Additionally the user that created them will
    have their password set to 'spammer'.

    Pass the additional command-line argument "confirm" to perform the
    deletions and modifications.

    This will additionally display the IP address(es) of the spam submissions.
    '''
    assert confirm in (False, 'confirm')
    cursor = st.get_cursor()
    cursor.execute("""
       select packages.name, submitted_date, submitted_by, submitted_from
        from packages, journals
        where packages.name LIKE %s
          and packages.name = journals.name
          and action = 'create'
    """, (namepat,))

    if not confirm:
        print 'NOT taking any action; add "confirm" to the command line to act'

    users = set()
    ips = set()
    for name, date, by, ip in cursor.fetchall():
        ips.add(ip)
        users.add(by)
        print 'delete', name, 'submitted on', date
        if confirm:
            store.remove_package(name)

    print 'IP addresses of spammers to possibly block:'
    for ip in ips:
        print '  ', ip

    for user in users:
        print 'disable user', user
        if confirm:
            cursor.execute("update users set password='spammer' where name=%s",
                (user,))

def remove_package(store, name):
    ''' Remove a package from the database
    '''
    store.remove_package(name)
    print 'done'

def add_owner(store, package, owner):
    user = store.get_user(owner)
    if user is None:
        raise ValueError, 'user name unknown to me'
    if not store.has_package(package):
        raise ValueError, 'no such package'
    store.add_role(owner, 'Owner', package)

def delete_owner(store, package, owner):
    user = store.get_user(owner)
    if user is None:
        raise ValueError, 'user name unknown to me'
    if not store.has_package(package):
        raise ValueError, 'no such package'
    for role in store.get_package_roles(package):
        if role['role_name']=='Owner' and role['user_name']==owner:
            break
    else:
        raise ValueError, "user is not currently owner"
    store.delete_role(owner, 'Owner', package)

def add_classifier(st, classifier):
    ''' Add a classifier to the trove_classifiers list
    '''
    cursor = st.get_cursor()
    cursor.execute("select max(id) from trove_classifiers")
    id = cursor.fetchone()[0]
    if id:
        id = int(id) + 1
    else:
        id = 1
    fields = [f.strip() for f in classifier.split('::')]
    for f in fields:
        assert ':' not in f
    levels = []
    for l in range(2, len(fields)):
        c2 = ' :: '.join(fields[:l])
        store.safe_execute(cursor, 'select id from trove_classifiers where classifier=%s', (c2,))
        l = cursor.fetchone()
        if not l:
            raise ValueError, c2 + " is not a known classifier"
        levels.append(l[0])
    levels += [id] + [0]*(3-len(levels))
    store.safe_execute(cursor, 'insert into trove_classifiers (id, classifier, l2, l3, l4, l5) '
        'values (%s,%s,%s,%s,%s,%s)', [id, classifier]+levels)

def rename_package(store, old, new):
    ''' Rename a package. '''
    if not store.has_package(old):
        raise ValueError, 'no such package'
    if store.has_package(new):
        raise ValueError, new+' exists'
    store.rename_package(old, new)
    print "Please give www-data permissions to all files of", new

def add_mirror(store, root, user):
    ''' Add a mirror to the mirrors list
    '''
    store.add_mirror(root, user)

    print 'done'

def delete_mirror(store, root):
    ''' Delete a mirror
    '''
    store.delete_mirror(root)
    print 'done'

def delete_old_docs(config, store):
    '''Delete documentation directories for packages that have been deleted'''
    for i in os.listdir(config.database_docs_dir):
        if not store.has_package(i):
           path = os.path.join(config.database_docs_dir, i)
           print "Deleting", path
           shutil.rmtree(path)

def keyrotate(config, store):
    '''Rotate server key'''
    key_dir = config.key_dir
    prefixes = (os.path.join(key_dir, 'privkey'), os.path.join(key_dir,'pubkey'))
    def rename_if_exists(oldsuffix, newsuffix):
        for p in prefixes:
            if os.path.exists(p+oldsuffix):
                os.rename(p+oldsuffix, p+newsuffix)
    # 1. generate new new key
    os.system('openssl dsaparam -out /tmp/param 2048')
    os.system('openssl gendsa -out %s/privkey.newnew /tmp/param' % key_dir)
    os.system('openssl dsa -in %s/privkey.newnew -pubout -out %s/pubkey.newnew' % (key_dir, key_dir))
    os.unlink('/tmp/param')
    # 2. delete old old key
    for p in prefixes:
        if os.path.exists(p+'.old'):
            os.unlink(p+'.old')
    # 3. rotate current key -> old key
    rename_if_exists('', '.old')
    # 4. rotate new key -> current key
    rename_if_exists('.new', '')
    # 5. rotate new new key -> new key
    rename_if_exists('.newnew', '.new')
    # 6. restart web server
    os.system('/usr/sbin/apache2ctl graceful')
    # 7. log rotation
    store.log_keyrotate()

def merge_user(store, old, new):
    c = store.get_cursor()
    if not store.get_user(old):
        print "Old does not exist"
        raise SystemExit
    if not store.get_user(new):
        print "New does not exist"
        raise SystemExit

    c.execute('update openids set name=%s where name=%s', (new, old))
    c.execute('update sshkeys set name=%s where name=%s', (new, old))
    c.execute('update roles set user_name=%s where user_name=%s', (new, old))
    c.execute('delete from rego_otk where name=%s', (old,))
    c.execute('update journals set submitted_by=%s where submitted_by=%s', (new, old))
    c.execute('update mirrors set user_name=%s where user_name=%s', (new, old))
    c.execute('update comments set user_name=%s where user_name=%s', (new, old))
    c.execute('update ratings set user_name=%s where user_name=%s', (new, old))
    c.execute('update comments_journal set submitted_by=%s where submitted_by=%s', (new, old))
    c.execute('delete from users where name=%s', (old,))

def show_user(store, name):
    user = store.get_user(name)
    if not user:
        sys.exit('user %r does not exist' % name)
    for key in user.keys():
        print '%s: %s' % (key, user[key])
    for p in store.get_user_packages(name):
        print '%s: %s' % (p['package_name'], p['role_name'])

def nuke_nested_lists(store, confirm=False):
    c = store.get_cursor()
    c.execute("""select name, version, summary from releases
        where summary like '%nested lists%'""")
    hits = {}
    for name, version, summary in c.fetchall():
        if "printer of nested lists" in summary:
            hits[name] = summary
            continue
        for f in store.list_files(name, version):
            path = store.gen_file_path(f['python_version'], name, f['filename'])
            if path.endswith('.zip'):
                z = zipfile.ZipFile(path)
                for i in z.infolist():
                    if not i.filename.endswith('.py'): continue
                    if 'def print_lol' in z.read(i.filename):
                        hits[name] = summary
            elif path.endswith('.tar.gz'):
                z = gzip.GzipFile(path)
                t = tarfile.TarFile(fileobj=z)
                for i in t.getmembers():
                    if not i.name.endswith('.py'): continue
                    f = t.extractfile(i.name)
                    if 'def print_lol' in f.read():
                        hits[name] = summary
    for name in hits:
        if confirm:
            store.remove_package(name)
        print '%s: %s' % (name, hits[name])
    if confirm:
        print 'removed %d packages' % len(hits)
    else:
        print 'WOULD HAVE removed %d packages' % len(hits)

if __name__ == '__main__':
    config = config.Config('/data/pypi/config.ini')
    st = store.Store(config)
    st.open()
    command = sys.argv[1]
    args = (st, ) + tuple(sys.argv[2:])
    try:
        if command == 'password':
            set_password(*args)
        elif command == 'rmpackage':
            remove_package(*args)
        elif command == 'rmspam':
            remove_spam(*args)
        elif command == 'addclass':
            add_classifier(*args)
            print 'done'
        elif command == 'addowner':
            add_owner(*args)
        elif command == 'delowner':
            delete_owner(*args)
        elif command == 'rename':
            rename_package(*args)
        elif command == 'addmirror':
            add_mirror(*args)
        elif command == 'delmirror':
            delete_mirror(*args)
        elif command == 'delolddocs':
            delete_old_docs(config, *args)
        elif command == 'send_comments':
            send_comments(*args)
        elif command == 'mergeuser':
            merge_user(*args)
        elif command == 'nuke_nested_lists':
            nuke_nested_lists(*args)
        elif command == 'keyrotate':
            keyrotate(config, *args)
        elif command == 'user':
            show_user(*args)
        else:
            print "unknown command '%s'!"%command
        st.changed()
    finally:
        st.close()

