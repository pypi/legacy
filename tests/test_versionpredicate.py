"""Tests harness for distutils.versionpredicate.

"""

import doctest
import unittest

import versionpredicate


def test_suite():
   return doctest.DocTestSuite(versionpredicate)


if __name__ == "__main__":
   unittest.main(defaultTest="test_suite")
