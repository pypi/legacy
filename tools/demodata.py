#!/usr/bin/python
import sys, os, urllib

root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(root)
# Work around http://sourceforge.net/p/docutils/bugs/214/
import docutils.utils
import admin, store, config

cfg = config.Config(root+'/config.ini')
st = store.Store(cfg)

# classifiers
for c in urllib.urlopen("http://pypi.python.org/pypi?%3Aaction=list_classifiers").read().splitlines():
    admin.add_classifier(st, c)

# Demo data starts here

# an admin
otk = st.store_user('fred', 'fredpw', 'fred@python.test')
st.delete_otk(otk)
st.add_role('fred', 'Admin', None)
# an owner
otk = st.store_user('barney', 'barneypw', 'barney@python.test')
st.delete_otk(otk)

# package spam
st.set_user('barney', '127.0.0.1', True)
for version in ('0.8', '0.9', '1.0'):
    st.store_package('spam', version, {
            'author':'Barney Geroellheimer',
            'author_email':'barney@python.test',
            'homepage':'http://spam.python.test/',
            'license':'GPL',
            'summary':'The spam package',
            'description': 'spam '*500,
            'classifiers':["Development Status :: 6 - Mature",
                           "Programming Language :: Python :: 2"],
            '_pypi_hidden':False
            })

# package eggs
for version in ('0.1', '0.2', '0.3', '0.4'):
    st.store_package('eggs', version, {
            'author':'Barney Geroellheimer',
            'author_email':'barney@python.test',
            'homepage':'http://eggs.python.test/',
            'license':'GPL',
            'summary':'The eggs package',
            'description':'Does anybody want to provide real data here?',
            'classifiers':["Development Status :: 3 - Alpha",
                           "Programming Language :: Python :: 3"],
            'requires_dist':['spam'],
            '_pypi_hidden':version!='0.4'
            })

st.add_file('spam', '1.0', 'THIS IS SOME CONTENT', '1234', 'sdist',
            'any', '', 'demo.txt', None)

st.commit()
