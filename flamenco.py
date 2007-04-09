#!/usr/bin/python

import sys, pprint, cgi, urllib, os, time, cStringIO

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
    def __init__(self, store, cursor, trove, query=[]):
        self.store = store
        self.cursor = cursor
        self.trove = trove
        self.query = query
        self.field_list = []
        self.boxes = None # may be cached boxes
        intersect = '' # SQL intersect statement of all query fields
        for group, tid in query:
            try:
                tid = int(tid)
            except ValueError:
                # skip invalid input
                continue
            self.field_list.append(self.trove[tid].path_split)
            sql = '(select name,version from release_classifiers where trove_id=%d' % tid
            for stid in trove[tid].subtree_ids()[1:]:
                sql += ' or trove_id=%d' % stid
            sql += ')'
            if intersect:
                intersect += 'intersect'+sql
            else:
                intersect = sql

        if not intersect and self.cached_tally():
            return
        
        if intersect:
            # Create a temporary table for all selected packages
            cursor.execute('create temporary table flamenco as '+intersect)

            # get the packages that match the query
            cursor.execute('''
select rc.trove_id, f.name,f.version,r.summary from release_classifiers rc, flamenco f inner join releases r on f.name=r.name and f.version=r.version and r._pypi_hidden=FALSE where rc.version=f.version and rc.name=f.name
''')

        else:
            cursor.execute('''
            select rc.trove_id, r.name, r.version, r.summary from release_classifiers rc, releases r where rc.version=r.version and rc.name=r.name and r._pypi_hidden=FALSE''')

        # Now sort into useful structures
        self.by_classifier = {}
        self.by_package = {}
        self.pkg_summary = {}
        for tid, name, version, summary in self.cursor.fetchall():
            if not isinstance(name, unicode):
                name = name.decode('utf-8')
            if not isinstance(version, unicode):
                version = version.decode('utf-8')
            if summary and not isinstance(summary, unicode):
                summary = summary.decode('utf-8')
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

        if intersect:
            cursor.execute('drop table flamenco')
        else:
            self.save_tally_cache()

    def cached_tally(self):
        self.cursor.execute("select value from timestamps where name='browse_tally'")
        dates = self.cursor.fetchall()
        if time.time()-dates[0][0].ticks() < 5*60:
            # Load tally from cache
            self.cursor.execute("select trove_id, tally from browse_tally")
            self.boxes = []
            sub = {}
            for tid, tally in self.cursor.fetchall():
                path = self.trove[tid].path_split
                assert len(path)==2, repr(path)
                d = sub.setdefault(path[0], {})
                d[path] = [None]*tally
            for field, d in sub.items():
                self.boxes.append((field, None, d.items()))
            return True
        # Need to generate cache
        return False

    def save_tally_cache(self):
        self.cursor.execute("delete from browse_tally")
        # Using PostgreSQL COPY here, instead of a series of INSERT statements
        s = cStringIO.StringIO()
        for _, _, items in self.list_choices()[1]:
            for path, packages in items:
                s.write('%d\t%d\n' % (self.trove.getid(path), len(packages)))
        s.seek(0)
        self.cursor.copy_from(s, 'browse_tally')
        self.cursor.execute("update timestamps set value=now() where name='browse_tally'")
        self.store.commit()

    def get_matches(self, addl_fields=[]):
        matches = {}
        # no need to check self.field_list anymore: all packages will
        # match field_list.
        for package, classifiers in self.by_package.items():
            for required in addl_fields:
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
        if self.boxes:
            # Cached tally
            return [], self.boxes
        
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

    def as_href(self, ignore=None, add=None, show=None):
        L = []
        if add is not None:
            L.append(urllib.quote('c', safe="") + '=' + 
                urllib.quote(str(add), safe=""))
        if show is not None:
            L.append(urllib.quote('show', safe="") + '=' + 
                urllib.quote(str(show), safe=""))
        for fld, value in self.query:
            if ignore == value:
                continue
            L.append(urllib.quote(fld, safe="") + '=' +
                     urllib.quote(str(value), safe=""))
        # Canonicalize query parameters, to prevent spiders
        # from downloading all permutations
        L.sort()
        return '&'.join(L)

