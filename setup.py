#! /usr/bin/env python
#
# $Id$

from distutils.core import setup

# perform the setup action
from webunit import __version__
setup(
    name = "pypi", 
    version = '2004-06-21',
    description = 
        "PyPI is the Python Package Index at http://www.python.org/pypi",
    long_description = '''This release, courtesy of Christopher Arndt, includes:
- when displaying a package and no version is given, try to determine
  the latest release  (bug #958515)
- better error handling in display action
- fixed page titles for search_form and forgotten_password_form
- fixed typo in store.py which prevented indexes being created
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
