#! /usr/bin/env python
#
# $Id$

from distutils.core import setup

# perform the setup action
from webunit import __version__
setup(
    name = "pypi", 
    version = '2004-03-01',
    description = 
        "PyPI is the Python Package Index at http://www.python.org/pypi",
    long_description = '''This release includes:

- add meaningful titles to pages (uses page heading)
- properly unquote version numbers for release editing page (bug #855883)
- allow removal of more than one release at a time
- make "delete whole package" a form button
- made wording of role admin link more helpful
- hide all current releases when a new release is added
''',
    author = "Richard Jones",
    author_email = "richard@mechanicalcat.net",
    url = 'http://www.python.org/pypi',
    classifiers = [
        'Development Status :: 5 - Production/Stable',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Natural Language :: English',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Software Development :: Libraries',
    ],
)

# vim: set filetype=python ts=4 sw=4 et si
