#!/usr/bin/env python2
# 
# $Id$

import sys, os, cgi, StringIO, traceback

#
# Provide interface to CGI HTTP response handling
#
class RequestWrapper:
    '''Used to make the CGI server look like a BaseHTTPRequestHandler
    '''
    def __init__(self, config, wfile):
        self.wfile = wfile
        self.config = config
    def send_response(self, code):
        self.wfile.write('Status: %s\r\n'%code)
    def send_header(self, keyword, value):
        self.wfile.write("%s: %s\r\n" % (keyword, value))
    def end_headers(self):
        self.wfile.write("\r\n")

#
# Main CGI handler
#
def main(request):
    handler = WebUI(request, os.environ)
    try:
        handler.run()
    except Unauthorised:
        request.send_response(403)
        request.send_header('Content-Type', 'text/html')
        request.end_headers()
        request.wfile.write('Unauthorised')
    except NotFound:
        request.send_response(404)
        request.send_header('Content-Type', 'text/html')
        request.end_headers()
        request.wfile.write('Not found: %s'%client.path)

#
# Now do the actual CGI handling
#
out, err = sys.stdout, sys.stderr
try:
    sys.path.insert(0, '/home/rjones/src/distutils_rego')
    from webui import WebUI
    import config
    cfg = config.Config('/home/rjones/src/distutils_rego/config.ini', 'webui')
    request = RequestWrapper(cfg, out)
    # force input/output to binary (important for file up/downloads)
    main(request)
except SystemExit:
    pass
except:
    out.write('Status: 400\nContent-Type: text/html\n\n')
    out.write("<pre>")
    s = StringIO.StringIO()
    traceback.print_exc(None, s)
    out.write(cgi.escape(s.getvalue()))
    out.write("</pre>\n")

sys.stdout.flush()

# vim: set filetype=python ts=4 sw=4 et si
