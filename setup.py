#! /usr/bin/env python
#
# $Id$

from distutils.core import setup

# perform the setup action
setup(
    name = "pypi",
    version = '2004-07-14',
    description =
        "PyPI is the Python Package Index at http://www.python.org/pypi",
    long_description = '''This release fixes a bug:

- fixed editing of package information in package summary page (bug 989597)
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
