#!/usr/bin/python

import sys
import sqlite

class Node:
    def __init__(self, id=None, name=None, path=None, path_split=None):
        self.arcs = {}
        self.id = id
        self.name = name
        self.path = path
        self.path_split = path_split

    def __repr__(self):
        return '<Node %d %s>'%(self.id, self.name)

class Trove:
    def __init__(self, cursor):
        self.root = Node()
        self.trove = {}
        cursor.execute('select * from trove_classifiers order by classifier')

        # now generate the tree
        for id, line in cursor.fetchall():
            id = int(id)
            d = self.root
            # make this a tuple so we can use it as a key
            path_split = tuple([s.strip() for s in line.split('::')])
            for arc in path_split:
                if d.arcs.has_key(arc):
                    d = d.arcs[arc]
                else:
                    n = Node(id, arc, line.strip(), path_split)
                    self.trove[id] = n
                    d.arcs[arc] = n
                    d = n
        self.FIELDS = self.root.arcs.keys()

    def getid(self, path):
        node = self.root
        for arc in path:
            node = node.arcs[arc]
        return node.id

    def __getitem__(self, key):
        return self.trove[key]

    EXCLUSIVE_FIELDS = {
        'Development Status':1,
        'Natural Language':1,
        'License':1,
    }

if __name__ == '__main__':
    db = sqlite.connect(db=sys.argv[1])
    trove = Trove(db.cursor())
    import dumper
    dumper.dump(trove)

