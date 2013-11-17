#!/usr/bin/python
#
# $Id$

import sys, os, cgi, StringIO, traceback
from BaseHTTPServer import BaseHTTPRequestHandler, DEFAULT_ERROR_MESSAGE

# turn this on if you need to do server maintenance
if 0:
    sys.stdout.write('Status: 503 Server down for maintenance\r\n')
    sys.stdout.write('Content-Type: text/plain\r\n\r\n')
    print 'The Cheese Shop server is down for a short time for maintenance.'
    print 'Please try to connect later.'
    sys.exit(0)

#
# Provide interface to CGI HTTP response handling
#
class RequestWrapper:
    '''Used to make the CGI server look like a BaseHTTPRequestHandler
    '''
    def __init__(self, config, rfile, wfile):
        self.wfile = wfile
        self.rfile = rfile
        self.config = config
    def send_response(self, code, message=''):
        self.wfile.write('Status: %s %s\r\n'%(code, message))
    def send_header(self, keyword, value):
        self.wfile.write("%s: %s\r\n" % (keyword, value))
    def set_content_type(self, content_type):
        self.send_header('Content-Type', content_type)
    def end_headers(self):
        self.wfile.write("\r\n")

#
# Now do the actual CGI handling
#
try:
    sys.path.insert(0, '/data/pypi/src/pypi')
    from webui import WebUI
    import config
    cfg = config.Config(os.environ.get("PYPI_COFNIG", "config.ini"))
    request = RequestWrapper(cfg, sys.stdin, sys.stdout)
    handler = WebUI(request, os.environ)
    handler.run()
except SystemExit:
    pass
except:
    sys.stdout.write('Status: 500 Internal Server Error\r\n')
    sys.stdout.write('Content-Type: text/html\r\n\r\n')
    sys.stdout.write("<pre>")
    s = StringIO.StringIO()
    traceback.print_exc(None, s)
    sys.stdout.write(cgi.escape(s.getvalue()))
    sys.stdout.write("</pre>\n")

# vim: set filetype=python ts=4 sw=4 et si
