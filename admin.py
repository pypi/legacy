
import sys, os, urllib, StringIO, traceback, cgi, binascii, getopt

import store, config

def set_password(store, name, pw):
    ''' Reset the user's password and send an email to the address given.
    '''
    user = store.get_user(name.strip())
    if user is None:
        raise ValueError, 'user name unknown to me'
    store.store_user(user['name'], pw.strip(), user['email'])
    print 'done'

if __name__ == '__main__':
    config = config.Config('/usr/local/pypi/config.ini', 'webui')
    store = store.Store(config)
    store.open()
    try:
        set_password(store, sys.argv[1], sys.argv[2])
        store.commit()
    finally:
        store.close()

