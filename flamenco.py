#!/usr/bin/python

import sys, pprint, cgi, urllib, os
import sqlite

class Query:
    """ Represents a Flamenco-style query.

        .query : (string, int)
         Maps top-level classifier names (e.g. 'Environment', or 'Topic')
         to an integer representing the value to be searched for.  Top-level
         classifiers can be specified multiple times.
    """
    def __init__(self, cursor, trove, field_list=[]):
        self.cursor = cursor
        self.trove = trove
        q = []
        self.queried_ids = {}
        for name, value in field_list:
            q.append((name, int(value)))
            self.queried_ids[value] = 1
        self.query = tuple(q)

    def get_values(self, field):
        """get_values(field:string) : [string]
        Return list of values requested for this field.
        """
        results = []
        for fld, value in self.query:
            if field == fld:
                results.append(value)
        return results

    def list_choices(self):
        matches = self.get_matches()
        boxes = []

        # get the per-classifier totals
        self.cursor.execute('''
select count(*),rc.trove_id
from releases r, release_classifiers rc
where r.name=rc.name and r.version=rc.version
  and r._pypi_hidden=0
group by rc.trove_id
''')
        counts = {}
        for count, tid in self.cursor.fetchall():
            counts[int(tid)] = int(count)

        # Loop through the available fields and list choices
        q = self.query

        for fld in self.trove.FIELDS:
            # If it's not an exclusive field, add a box listing all of the
            # top-level options.
            values = self.get_values(fld)
            if not values or not self.trove.EXCLUSIVE_FIELDS.has_key(fld):
                L = []
                for node in self.trove.root.arcs[fld].arcs.values():
                    if not self.queried_ids.has_key(node.id):
                        count = counts.get(node.id, 0)
                        if count:
                            L.append((node.name, node.id, count))
                L.sort()
                boxes.append((fld, fld, L, None))

            # If a value is specified for this field, we need to check
            # for the sub-options for the user's choice, so they can drill
            # down further.
            for v1 in values:
                # Are there any matching subtrees?
                # (Environment::Console has subtrees ::Curses, ::Newt, &c.)
                node = self.trove[v1]
                if len(node.arcs) == 0:
                    # No, no subtrees
                    continue

                # Otherwise, list the possible choices
                L = []
                for n in node.arcs.values():
                    # XXX should count up the number of matching packages
                    # for each key 
                    newq = self.copy()
                    newq.set_field(fld, v1, node.id)
                    count = newq.get_match_count()
                    if count:
                        L.append((n.name, n.id, count))
                L.sort()
                boxes.append((fld, node.path, L, v1))

        return matches, boxes

    def get_matches(self):
        # Return list of matches for current query
        if len(self.query) == 0:
            self.cursor.execute('select distinct name, version from releases '
                'where _pypi_hidden = 0')
            L = self.cursor.fetchall()
            L = [tuple(x) for x in L]
            return L

        # grab all the matching release classifiers
        sql = '''
 select r.summary, rc.name, rc.version
 from releases r, release_classifiers rc
 where rc.trove_id = %s
   and r.name=rc.name and r.version=rc.version
   and r._pypi_hidden=0
'''
        tids = 'intersect'.join([sql%id for field,id in self.query])
        self.cursor.execute(tids)
        result = self.cursor.fetchall()
        if result is None:
            return []

        # unpack the row results and ... pack them up again ;)
        return result

    def get_match_count(self):
        return len(self.get_matches())
    
    def as_href(self):
        L = []
        for fld, value in self.query:
            L.append(urllib.quote(fld, safe="") + '=' +
                     urllib.quote(str(value), safe=""))
        return '&'.join(L)

    def remove_field(self, field, old_value):
        L = list(self.query)
        for i in range(len(L)):
            if (L[i][0] == field and
                L[i][1] == old_value ):
                    del L[i]
                    break
        self.query = tuple(L)
        
        
    def set_field(self, field, old_value, new_value):
        L = list(self.query)
        for i in range(len(L)):
            if (L[i][0] == field and
                L[i][1] == old_value ):
                v = list(L[i])
                v[1] = new_value
                L[i] = tuple(v)
                break
        else:
            # Not found, so just add it
            L.append((field, new_value))
        self.query = tuple(L)

    def copy(self):
        q = Query(self.cursor, self.trove)
        q.query = self.query[:]
        return q

if __name__ == '__main__':
    db = sqlite.connect(db=sys.argv[1])

    import trove
    trove = trove.Trove(db.cursor())

#    print "*** Development Status=Beta"
#    q = Query(db.cursor(), trove, [('Development Status', '4')])
#    v = q.list_choices()
#    pprint.pprint(v)
    
    print "*** Topic :: Software Development"
    q = Query(db.cursor(), trove, [('Topic', '405')])
    v = q.list_choices()
    pprint.pprint(v)
    print q.as_href()

