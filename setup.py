#! /usr/bin/env python
#
# $Id$

from distutils.core import setup

# perform the setup action
from webunit import __version__
setup(
    name = "pypi", 
    version = '2004-03-02',
    description = 
        "PyPI is the Python Package Index at http://www.python.org/pypi",
    long_description = '''This release includes:
- fixed deletion of packages where there were no versions (bugs #907317 and
  #908118)
- list only new releases in RSS and front page, not any old edit (bug
  #907315)
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
