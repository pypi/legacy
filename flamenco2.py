#!/usr/bin/python

import sys, pprint, cgi, urllib, os

def flatten(d):
    l = d[1]
    for entry in d[0].values():
        l += flatten(entry)
    return l

class Query:
    """ Represents a Flamenco-style query.

        .query : (string, int)
         Maps top-level classifier names (e.g. 'Environment', or 'Topic')
         to an integer representing the value to be searched for.  Top-level
         classifiers can be specified multiple times.
    """
    def __init__(self, cursor, trove, query=[]):
        self.cursor = cursor
        self.trove = trove
        self.query = query
        self.field_list = []
        for group, tid in query:
            try:
                int(tid)
            except ValueError:
                # skip invalid input
                continue
            self.field_list.append(self.trove[int(tid)].path_split)

        # get the packages that match classifiers
        self.cursor.execute('''
select rc.trove_id, r.name, r.version, r.summary
from releases r, release_classifiers rc
where r.name=rc.name and r.version=rc.version
  and r._pypi_hidden=FALSE
''')

        # Now sort into useful structures
        self.by_classifier = {}
        self.by_package = {}
        self.pkg_summary = {}
        for tid, name, version, summary in self.cursor.fetchall():
            self.pkg_summary[(name, version)] = summary
            l = self.trove[int(tid)].path_split
            self.by_package.setdefault((name, version), []).append(l)
            d = self.by_classifier
            for arc in l[:-1]:
                if not d.has_key(arc):
                    d[arc] = ({}, [])
                d = d[arc][0]
            arc = l[-1]
            if not d.has_key(arc):
                d[arc] = ({}, [])
            d[arc][1].append((name, version))

    def get_matches(self, addl_fields=[]):
        matches = {}
        query_fields = self.field_list + addl_fields
        for package, classifiers in self.by_package.items():
            for required in query_fields:
                # make sure the field appears in this package's classifiers
                for classifier in classifiers:
                    if classifier[:len(required)] == required:
                        # match, yay
                        break
                else:
                    # no classifier matched the required query_field
                    break
            else:
                # passed all the query classifiers
                matches[package] = self.pkg_summary[package]
        return [k+(v,) for k,v in matches.items()]

    def list_choices(self):
        # match the packages based on the current query
        packages = self.get_matches()

        # see which classifiers are left over
        classifiers = {}
        for name, version, summary in packages:
            for classifier in self.by_package[(name, version)]:
                classifiers.setdefault(classifier, {})[(name, version)] = 1

        sub = {}
        # organise boxes based on possible sub-queries
        for classifier in classifiers.keys():
            for field in self.field_list:
                if len(classifier) <= len(field):
                    continue
                if classifier[:len(field)] != field:
                    continue
                d = sub.setdefault(field, {})
                matches = self.get_matches(addl_fields=[classifier])
                d[classifier[:len(field)+1]] = matches

        # first set of boxes
        boxes = []
        for field, d in sub.items():
            fid = self.trove.getid(field)
            boxes.append((' :: '.join(field), fid, d.items()))

        # now other fields we may match that aren't already part of the
        # query
        sub = {}
        for classifier, count in classifiers.items():
            field = classifier[0]
            classifier = classifier[:2]
            d = sub.setdefault(field, {})
            matches = self.get_matches(addl_fields=[classifier])
            d[classifier] = d.get(classifier, []) + matches

        # now add those boxes - filter out duplicates
        for field, d in sub.items():
            # top-level fields don't have meaningful ids
            for k,v in d.items():
                n = {}
                for p in v:
                    n[p] = 1
                d[k] = n.keys()
            boxes.append((field, None, d.items()))

        return packages, boxes

    def as_href(self, ignore=None, add=None):
        L = []
        if add is not None:
            L.append(urllib.quote('asdf', safe="") + '=' + 
                urllib.quote(str(add), safe=""))
        for fld, value in self.query:
            if ignore == value:
                continue
            L.append(urllib.quote(fld, safe="") + '=' +
                     urllib.quote(str(value), safe=""))
        return '&'.join(L)

