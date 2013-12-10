import unittest 
import os
import sys
from mx.DateTime import DateTime
from StringIO import StringIO
import csv
import shutil

# just to make sur we can launch it 
# from the top folder
curdir = os.path.dirname(__file__)
topdir = os.path.realpath(os.path.split(curdir)[0])

bz2_file = os.path.join(curdir, 'stats.bz2')
stats_file = os.path.join(curdir, '2008-11-18.bz2')

if topdir not in sys.path:
    sys.path.insert(0, topdir)

from apache_reader import ApacheLogReader
from apache_count import main
from apache_stats import ApacheLocalStats
from apache_stats import ApacheDistantLocalStats

log_sample = os.path.join(curdir, 'pypi.access.log.1.bz2')
config_file =  os.path.join(curdir, 'pypi.cfg')
mirror =  os.path.join(curdir, 'mirror')
mirrors =  os.path.join(curdir, 'mirrors')
local_stats =  os.path.join(curdir, 'local-stats')
global_stats =  os.path.join(curdir, 'global-stats')

import apache_count

class FakeCursor(object):

    def __init__(self):
        self.res = None
        self._data = [('Package', 'Package.tgz', 2), ]
        self._index = 0

    def execute(self, query, args=None):
        if query.startswith('select value from timestamps'):
            self.res = [[DateTime(1900, 01, 01)]]
        elif query.startswith('select downloads'):
            self.res = [[0]]

    def fetchone(self):
        return self.res[0]

    def fetchall(self):
        mirror = ['http://somewhere.com', 'xx', 'xxx', 'here']
        return [mirror]

    def __iter__(self):
        return self

    def next(self):
        try:
            try:
                return self._data[self._index]
            except IndexError:
                raise StopIteration
        finally:
            self._index += 1

class FakeConn(object):
    def commit(self):
        pass

def _get_cursor(config):
    return FakeConn(), FakeCursor()

apache_count.get_cursor = _get_cursor

class TestApacheReader(unittest.TestCase):
   
    def setUp(self):
        for folder in (local_stats, global_stats):
            if os.path.exists(folder):
                continue
            os.mkdir(folder)

    def tearDown(self):
        if os.path.exists(bz2_file):
            os.remove(bz2_file)
        if os.path.exists(stats_file):
            os.remove(stats_file)
        if os.path.exists(mirror):
            shutil.rmtree(mirror)
        if os.path.exists(mirrors):
            shutil.rmtree(mirrors)
        for folder in (local_stats, global_stats):
            shutil.rmtree(folder)

    def _test_useragent(self):
        
        logs = ApacheLogReader(log_sample)
        logs = list(logs)
        self.assertEquals(logs[45]['useragent'], 
                          'Python-urllib/2.5 setuptools/0.6c7')

    def test_apache_count(self):

        # creating stats so they can be used by 
        # main() as distant stats
        stats = ApacheLocalStats()    
        stats.build_monthly_stats(2008, 11, log_sample, 
                                  bz2_file, compression='bz2') 
        # now patching url so it return the built stats
        import urllib2
        old_open = urllib2.urlopen
        def _open(url):
            class FakeUrl(object):
                def read(self):
                    return open(bz2_file).read()
            return FakeUrl()
        urllib2.urlopen = _open

        # just to make sure it doesn't brake
        try:
            main(config_file, log_sample)        
        finally:
            urllib2.urlopen = old_open
        
    def test_build_daily_stats(self):
        stats = ApacheLocalStats()
        results = StringIO()
        stats.build_daily_stats(2008, 11, 18, log_sample, results)
        results.seek(0)

        reader = csv.reader(results)
        res = list(reader)

        # first, make sure all entries have values
        for line in res:
            self.assertEquals(len(line), 4)
            self.assert_('' not in line)

        self.assertEquals(res[0], 
              ['4Suite-XML', '4Suite-XML-1.0.1.tar.bz2', 'Mozilla/5.0', '1'])
        self.assertEquals(res[456],
              ['PasteScript', 'PasteScript-0.3.1.tar.gz', 'Mozilla/5.0', '1'])
        self.assertEquals(res[486],
              ['Phebe', 'Phebe-0.1.1-py2.5.egg.asc', 'Mozilla/5.0', '1'])
        
        self.assertEquals(len(res), 8953)

    def test_user_agent(self):
        logs = ApacheLogReader(log_sample)
        res = logs.get_simplified_ua('Python-urllib/2.5 setuptools/0.6c7')
        self.assertEquals(res, 'setuptools/0.6c7')
        
        res = logs.get_simplified_ua('Python-urllib/2.4')
        self.assertEquals(res, 'Python-urllib/2.4')

        safari = ('Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_5_5; it-it) '
                  'AppleWebKit/525.26.2 (KHTML, like Gecko) Version/3.2 Safari/525.26.12')
        res = logs.get_simplified_ua(safari)
        self.assertEquals(res, 'Safari/3.2')

        msn = 'msnbot/1.1 (+http://search.msn.com/msnbot.htm)'
        res = logs.get_simplified_ua(msn)
        self.assertEquals(res, 'msnbot/1.1')

        nokia = ('Nokia6820/2.0 (4.83) Profile/MIDP-1.0 Configuration/CLDC-1.0 '
                 '(compatible; Googlebot-Mobile/2.1; +http://www.google.com/bot.html)')
        res = logs.get_simplified_ua(nokia)
        self.assertEquals(res, 'Googlebot-Mobile/2.1')

        # firefox 2 or 3
        ff = 'Mozilla/5.0 (X11; U; Linux i686; fr; rv:1.8.1.3) Gecko/20070309 Firefox/2.0.0.3'
        res = logs.get_simplified_ua(ff)
        self.assertEquals(res, 'Firefox/2')

        ff3 = 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.4) Gecko/2008111318 Ubuntu/8.10 (intrepid) Firefox/3.0.4'
        res = logs.get_simplified_ua(ff3)
        self.assertEquals(res, 'Firefox/3')

        slurp = 'Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)'
        res = logs.get_simplified_ua(slurp)
        self.assertEquals(res, 'Mozilla/5.0')

    def test_build_monthly_stats(self):
        results = StringIO()
        stats = ApacheLocalStats()    
        stats.build_monthly_stats(2008, 11, log_sample, results)
        results.seek(0)

        reader = csv.reader(results)
        res = list(reader)

        # first, make sure all entries have values
        for line in res:
            self.assertEquals(len(line), 4)
            self.assert_('' not in line)
        
        self.assertEquals(res[0],
           ['appwsgi', '344.tar.bz2', 'Mozilla/5.0', '1'])

        self.assertEquals(res[456],
           ['Mtrax', 'Mtrax-2.2.07-py2.5-win32.egg', 'Firefox/3', '1'])
        
        self.assertEquals(res[486],
           ['OpenPGP', 'OpenPGP-0.2.3.tar.gz', 'Firefox/3', '1'])

        self.assertEquals(len(res), 10043)

    def test_read_stats(self):

        results = StringIO()
        stats = ApacheLocalStats()    
        stats.build_monthly_stats(2008, 11, log_sample, results)
        results.seek(0)
        
        read = stats.read_stats(results)
        first_entry = read.next()

        self.assertEquals(first_entry['count'], '1')
        self.assertEquals(first_entry['packagename'], 'appwsgi')

    def test_compression(self):
        stats = ApacheLocalStats()    
        stats.build_monthly_stats(2008, 11, log_sample, 
                                  bz2_file, compression='bz2') 
        
        read = stats.read_stats(bz2_file)
        first_entry = read.next()
        self.assertEquals(first_entry['count'], '1')
        self.assertEquals(first_entry['packagename'], 'appwsgi')

    def test_build_local_stats(self):

        # builds the standard stats local file
        stats = ApacheLocalStats()    
        stats.build_local_stats(2008, 11, 18, log_sample, curdir)
        self.assert_(os.path.exists(stats_file))

        read = stats.read_stats(stats_file)
        first_entry = read.next()
        self.assertEquals(first_entry['count'], '1')
        self.assertEquals(first_entry['packagename'], '4Suite-XML')


    def test_distant_stats(self):

        os.mkdir(mirror)
        url = 'http://example.com/mirror/daily/2008-11-18.bz2'
        stats = ApacheDistantLocalStats(mirror)
        
        self.assertEquals(list(stats.read_stats(url)), [])
       
        # let's build the stats
        local_stats = ApacheLocalStats()    
        local_stats.build_monthly_stats(2008, 11, log_sample, 
                                  bz2_file, compression='bz2') 
        
        # now patching url so it return the built stats
        import urllib2
        old_open = urllib2.urlopen
        def _open(url):
            class FakeUrl(object):
                def read(self):
                    return open(bz2_file).read()
            return FakeUrl()
        urllib2.urlopen = _open

        read = stats.read_stats(url)
        first_entry = read.next()

        self.assertEquals(first_entry['count'], '1')
        self.assertEquals(first_entry['packagename'], 'appwsgi')
        
        # checking that the cache is filled
        self.assert_('2008-11-18.bz2' in os.listdir(mirror))

        # removing the urlopen patch
        urllib2.urlopen = old_open
       
        # the cache should be activated now
        read = stats.read_stats(url) 
        first_entry = read.next()
        self.assertEquals(first_entry['count'], '1')
        self.assertEquals(first_entry['packagename'], 'appwsgi')


def test_suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(TestApacheReader))
    return suite

if __name__ == '__main__':
    unittest.main(defaultTest='test_suite')

