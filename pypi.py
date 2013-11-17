#!/usr/bin/python
#
# $Id$

import os.path
import sys

prefix = os.path.dirname(__file__)
sys.path.insert(0, prefix)

from mod_python import apache
import sys, os, cgi, StringIO, traceback
from BaseHTTPServer import BaseHTTPRequestHandler, DEFAULT_ERROR_MESSAGE
from webui import WebUI
import config

CONFIG_FILE = os.environ.get("PYPI_CONFIG", os.path.join(prefix, 'config.ini'))

class RequestWrapper:
    '''Used to make the CGI server look like a BaseHTTPRequestHandler
    '''
    def __init__(self, config, req):
        self.wfile = self.req = req
        self.rfile = StringIO.StringIO(req.read())
        self.config = config
    def send_response(self, code, message=''):
        self.req.status = code
    def send_header(self, keyword, value):
        self.req.headers_out[keyword] = value
    def set_content_type(self, content_type):
        self.req.content_type = content_type
    def end_headers(self):
        pass

def handle(req):
    req.content_type = req.headers_out['Content-Type'] = 'text/html'
    cfg = config.Config(os.environ.get("PYPI_COFNIG", CONFIG_FILE))
    request = RequestWrapper(cfg, req)
    pseudoenv = {}
    pseudoenv['CONTENT_TYPE'] = req.headers_in.get('content-type', '')
    pseudoenv['REMOTE_ADDR'] = req.get_remote_host(apache.REMOTE_NOLOOKUP)
    pseudoenv['HTTP_USER_AGENT'] = req.headers_in.get('user-agent', '')
    pseudoenv['QUERY_STRING'] = req.args
    pseudoenv['HTTP_CGI_AUTHORIZATION'] = req.headers_in.get('authorization',
        '')
    pseudoenv['REQUEST_METHOD'] = req.method
    path_info = req.path_info
    pseudoenv['PATH_INFO'] = path_info
    try:
        handler = WebUI(request, pseudoenv)
        handler.run()
    except:
        s = StringIO.StringIO()
        traceback.print_exc(None, s)
        req.write("<pre>")
        req.write(cgi.escape(s.getvalue()))
        req.write("</pre>")
        req.headers_out['Content-Type'] = 'text/html'
    req.content_type = req.headers_out['Content-Type']
    return apache.OK

# vim: set filetype=python ts=4 sw=4 et si
