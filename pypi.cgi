#!/usr/bin/env python2
# 
# $Id$

import sys, os, cgi, StringIO, traceback
from BaseHTTPServer import BaseHTTPRequestHandler, DEFAULT_ERROR_MESSAGE

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
    def send_error(self, code, message=''):
        short, long = BaseHTTPRequestHandler.responses[code]
        self.send_response(code)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(DEFAULT_ERROR_MESSAGE%{'code': code,
            'message': short, 'explain': message or long})
    def send_response(self, code):
        self.wfile.write('Status: %s\r\n'%code)
    def send_header(self, keyword, value):
        self.wfile.write("%s: %s\r\n" % (keyword, value))
    def end_headers(self):
        self.wfile.write("\r\n")

#
# Now do the actual CGI handling
#
try:
    sys.path.insert(0, '/home/rjones/src/pypi')
    from webui import WebUI
    import config
    cfg = config.Config('/home/rjones/src/pypi/config.ini', 'webui')
    request = RequestWrapper(cfg, sys.stdin, sys.stdout)
    handler = WebUI(request, os.environ)
    handler.run()
except SystemExit:
    pass
except:
    sys.stdout.write('Status: 400\nContent-Type: text/html\n\n')
    sys.stdout.write("<pre>")
    s = StringIO.StringIO()
    traceback.print_exc(None, s)
    sys.stdout.write(cgi.escape(s.getvalue()))
    sys.stdout.write("</pre>\n")

# vim: set filetype=python ts=4 sw=4 et si
