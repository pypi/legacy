#!/usr/bin/python
import sys,os
prefix = os.path.dirname(__file__)
sys.path.insert(0, prefix)
import cStringIO, webui, store, config

store.keep_conn = True

class Request:

    def __init__(self, environ, start_response):
        self.start_response = start_response
        self.rfile = cStringIO.StringIO(environ['wsgi.input'].read())
        self.wfile = cStringIO.StringIO()
        self.config = config.Config(prefix+'/config.ini')
    
    def send_response(self, code, message='no details available'):
        self.status = '%s %s' % (code, message)
        self.headers = []
        
    def send_header(self, keyword, value):
        self.headers.append((keyword, value))

    def set_content_type(self, content_type):
        self.send_header('Content-Type', content_type)

    def end_headers(self):
        self.start_response(self.status, self.headers)

def debug(environ, start_response):
    if environ['PATH_INFO'].startswith("/auth") and \
           "HTTP_AUTHORIZATION" not in environ:
        start_response("401 login",
                       [('WWW-Authenticate', 'Basic realm="foo"')])
        return
    start_response("200 ok", [('Content-type', 'text/plain')])
    environ = environ.items()
    environ.sort()
    for k,v in environ:
        yield "%s=%s\n" % (k, v)
    return


def application(environ, start_response):
    if "HTTP_AUTHORIZATION" in environ:
        environ["HTTP_CGI_AUTHORIZATION"] = environ["HTTP_AUTHORIZATION"]
    r = Request(environ, start_response)
    webui.WebUI(r, environ).run()
    return [r.wfile.getvalue()]
