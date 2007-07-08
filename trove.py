#!/usr/bin/python

import sys

class Node:
    def __init__(self, id=None, name=None, path=None, path_split=None):
        self.arcs = {}
        self.id = id
        self.name = name
        self.path = path
        self.path_split = path_split
        if path_split:
            self.level = len(path_split)
        else:
            self.level = 1

    def __repr__(self):
        return '<Node %d %s>'%(self.id, self.name)

    def subtree_ids(self):
        result = [self.id]
        for node in self.arcs.values():
            result.extend(node.subtree_ids())
        return result

class Trove:
    def __init__(self, cursor):
        self.root = Node()
        self.trove = {}
        cursor.execute('select id,classifier from trove_classifiers order by classifier')

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

