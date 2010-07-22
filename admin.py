
import sys, os, urllib, StringIO, traceback, cgi, binascii, getopt, shutil
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

def send_comments(store):
    '''Send out comments to package owners. Normally, this will
    be done automatically, but the very first comments had not been sent.'''
    import webui
    c = store.get_cursor()
    c.execute("select name, version, user_name, message from ratings where message!=''")
    for package, version, author, comment in c.fetchall():
        webui.comment_email(store, package, version, author, comment)

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

if __name__ == '__main__':
    config = config.Config('/data/pypi/config.ini')
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
        else:
            print "unknown command '%s'!"%command
        store.changed()
    finally:
        store.close()

