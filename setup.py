#! /usr/bin/env python
#
# $Id$

from distutils.core import setup

# perform the setup action
setup(
    name = "pypi",
    version = '2005-08-01',
    description =
        "PyPI is the Python Package Index at http://pypi.python.org/",
    long_description = '''PyPI has a new home at
<http://pypi.python.org/>. Users should need not need to change
anything, as the old "www" address should still work. Use of the new
address in preference is encouraged.

Developers interested in how PyPI works, or in contributing to the project,
should visit http://wiki.python.org/moin/CheeseShopDev
''',
    author = "Richard Jones",
    author_email = "richard@python.org",
    url = 'http://wiki.python.org/moin/CheeseShopDev',
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
