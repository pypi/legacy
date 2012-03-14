#!/usr/bin/python
import sys,os
import cStringIO, webui, store, config
from wsgiref.simple_server import make_server

class Request:
    def __init__(self, environ, start_response, config):
        self.start_response = start_response
        try:
            length = int(environ['CONTENT_LENGTH'])
        except ValueError:
            length = 0
        self.rfile = cStringIO.StringIO(environ['wsgi.input'].read(length))
        self.wfile = cStringIO.StringIO()
        self.config = config.Config(config)

    def send_response(self, code, message='no details available'):
        self.status = '%s %s' % (code, message)
        self.headers = []

    def send_header(self, keyword, value):
        self.headers.append((keyword, value))

    def set_content_type(self, content_type):
        self.send_header('Content-Type', content_type)

    def end_headers(self):
        self.start_response(self.status, self.headers)

class Application:
    def __init__(self, config, debug=False):
        self.config = config

        if debug:
            self.__call__ = self.debug
        else:
            self.__call__ = self.application
            store.keep_conn = True

    def application(self, environ, start_response):
        if "HTTP_AUTHORIZATION" in environ:
            environ["HTTP_CGI_AUTHORIZATION"] = environ["HTTP_AUTHORIZATION"]
        r = Request(environ, start_response)
        webui.WebUI(r, environ).run()
        return [r.wfile.getvalue()]

    def debug(self, environ, start_response):
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

    def test(self, port):
        # very simple wsgi server so we can play locally
        httpd = make_server('', port, self)
        print "Serving on port %d..." % port
        httpd.serve_forever()

