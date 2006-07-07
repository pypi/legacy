#!/usr/bin/python
# 
# $Id$

from mod_python import apache
import sys, os, cgi, StringIO, traceback
from BaseHTTPServer import BaseHTTPRequestHandler, DEFAULT_ERROR_MESSAGE
from webui import WebUI
import config

class RequestWrapper:
    '''Used to make the CGI server look like a BaseHTTPRequestHandler
    '''
    def __init__(self, config, rfile, wfile):
        self.wfile = wfile
        self.rfile = rfile
        self.config = config
    def send_response(self, code, message=''):
        self.wfile.status = code
    def send_header(self, keyword, value):
        self.wfile.headers_out[keyword] = value
    def end_headers(self):
        pass

def handle(req):
    req.content_type = req.headers_out['Content-Type'] = 'text/html'
    cfg = config.Config('/data/pypi/config.ini', 'webui')
    s = req.read()
    rfile = StringIO.StringIO(s)
    request = RequestWrapper(cfg, rfile, req)
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
