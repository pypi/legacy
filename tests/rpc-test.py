import sys
import config
import store
import unittest
import rpc
import cStringIO

class XMLRPC ( unittest.TestCase ):

    def setUp( self ):
        # get a storage object to use in calls to xmlrpc functions
        self.store = store.Store( config.Config( "/tmp/pypi/config.ini", "webui" ) )

    def testEcho( self ):
        result = rpc.echo(self.store, 'a', 'b', 1, 3.4)
        self.failUnlessEqual(result, ('a', 'b', 1, 3.4))
        
    def testIndex( self ):
        result = rpc.index( self.store )
        self.failUnless( len( result ) > 0 )

    def testSearch( self ):
        result = rpc.search( self.store, "sql" )
        self.failUnless( len( result ) > 0 )

if __name__ == '__main__':
    unittest.main()
