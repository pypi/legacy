#!/usr/bin/python
import thfcgi, os, sys, StringIO, traceback, cgi

#
# Provide interface to CGI HTTP response handling
#
class RequestWrapper:
    '''Used to make the FCGI server look like a BaseHTTPRequestHandler
    '''
    def __init__(self, config, req):
        self.wfile = req.out
        self.rfile = req.stdin
        self.config = config
    def send_response(self, code, message=''):
        self.wfile.write('Status: %s %s\r\n'%(code, message))
    def send_header(self, keyword, value):
        self.wfile.write("%s: %s\r\n" % (keyword, value))
    def set_content_type(self, content_type):
        self.send_header('Content-Type', content_type)
    def end_headers(self):
        self.wfile.write("\r\n")

def handle_request(req, env):
    try:
        import store
        store.keep_conn = True
        from webui import WebUI
        request = RequestWrapper(cfg, req)
        handler = WebUI(request, env)
        handler.run()
    except SystemExit:
        pass
    except:
        req.out.write('Status: 500 Internal Server Error\r\n')
        req.out.write('Content-Type: text/html\r\n\r\n')
        req.out.write("<pre>")
        s = StringIO.StringIO()
        traceback.print_exc(None, s)
        req.out.write(cgi.escape(s.getvalue()))
        req.out.write("</pre>\n")
    req.finish()

#
# Now do the actual CGI handling
#
prefix = os.path.dirname(__file__)
sys.path.insert(0, prefix)
import config
cfg = config.Config(prefix+'/config.ini')
fcg = thfcgi.FCGI(handle_request, 
                  max_requests=-1,
                  backlog=50,
                  max_threads=1)
fcg.run()


