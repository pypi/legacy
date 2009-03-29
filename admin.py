
import sys, os, urllib, StringIO, traceback, cgi, binascii, getopt
sys.path.append('/usr/local/pypi/lib')

import store, config

def set_password(store, name, pw):
    """ Reset the user's password and send an email to the address given.
    """
    user = store.get_user(name.strip())
    if user is None:
        raise ValueError, 'user name unknown to me'
    store.store_user(user['name'], pw.strip(), user['email'], None)
    print 'done'


def remove_package(store, name):
    ''' Remove a package from the database
    '''
    cursor = store.get_cursor()
    cursor.execute('delete from release_classifiers where name=%s', [name])
    cursor.execute('delete from releases where name=%s', [name])
    cursor.execute('delete from roles where package_name=%s', [name])
    cursor.execute('delete from packages where name=%s', [name])
    cursor.execute('delete from journals where name=%s', [name])
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

def add_classifier(store, classifier):
    ''' Add a classifier to the trove_classifiers list
    '''
    cursor = store.get_cursor()
    cursor.execute("select max(id) from trove_classifiers")
    id = int(cursor.fetchone()[0]) + 1
    fields = [f.strip() for f in classifier.split('::')]
    for f in fields:
        assert ':' not in f
    levels = []
    for l in range(2, len(fields)):
        c2 = ' :: '.join(fields[:l])
        cursor.execute('select id from trove_classifiers where classifier=%s', (c2,))
        l = cursor.fetchone()
        if not l:
            raise ValueError, c2 + " is not a known classifier"
        levels.append(l[0])
    levels += [id] + [0]*(3-len(levels))
    cursor.execute('insert into trove_classifiers (id, classifier, l2, l3, l4, l5) '
        'values (%s,%s,%s,%s,%s,%s)', [id, classifier]+levels)
    print 'done'

def rename_package(store, old, new):
    ''' Rename a package. '''
    if not store.has_package(old):
        raise ValueError, 'no such package'
    if store.has_package(new):
        raise ValueError, new+' exists'
    store.rename_package(old, new)
    

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

if __name__ == '__main__':
    config = config.Config('/usr/local/pypi/config.ini', 'webui')
    store = store.Store(config)
    store.open()
    command = sys.argv[1]
    args = (store, ) + tuple(sys.argv[2:])
    try:
        if command == 'password':
            set_password(*args)
        elif command == 'rmpackage':
            remove_package(*args)
        elif command == 'addclass':
            add_classifier(*args)
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
        else:
            print "unknown command '%s'!"%command
        store.commit()
    finally:
        store.close()

