#!/usr/bin/python
import config, webui, BaseHTTPServer, urllib, sys, getopt

class RequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    config = config.Config("config.ini")

    def set_content_type(self, content_type):
        self.send_header('Content-Type', content_type)

    def run(self):
        for scriptname in ('/mirrors', '/simple', '/pypi'):
            if self.path.startswith(scriptname):
                rest = self.path[len(scriptname):]
                break
        else:
            # invalid URL
            return

        # The text below is mostly copied from CGIHTTPServer

        i = rest.rfind('?')
        if i >= 0:
            rest, query = rest[:i], rest[i+1:]
        else:
            query = ''            

        env = {}
        #env['SERVER_SOFTWARE'] = self.version_string()
        #env['SERVER_NAME'] = self.server.server_name
        #env['SERVER_PORT'] = str(self.server.server_port)
        env['GATEWAY_INTERFACE'] = 'CGI/1.1'
        env['SERVER_PROTOCOL'] = self.protocol_version
        env['REQUEST_METHOD'] = self.command
        uqrest = urllib.unquote(rest)
        env['PATH_INFO'] = uqrest
        # env['PATH_TRANSLATED'] = self.translate_path(uqrest)
        env['SCRIPT_NAME'] = scriptname
        if query:
            env['QUERY_STRING'] = query
        host = self.address_string()
        if host != self.client_address[0]:
            env['REMOTE_HOST'] = host
        env['REMOTE_ADDR'] = self.client_address[0]
        authorization = self.headers.getheader("authorization")
        if authorization:
            env['HTTP_CGI_AUTHORIZATION'] = authorization
            authorization = authorization.split()
            if len(authorization) == 2:
                import base64, binascii
                env['AUTH_TYPE'] = authorization[0]
                if authorization[0].lower() == "basic":
                    try:
                        authorization = base64.decodestring(authorization[1])
                    except binascii.Error:
                        pass
                    else:
                        authorization = authorization.split(':')
                        if len(authorization) == 2:
                            env['REMOTE_USER'] = authorization[0]
        if self.headers.typeheader is None:
            env['CONTENT_TYPE'] = self.headers.type
        else:
            env['CONTENT_TYPE'] = self.headers.typeheader
        length = self.headers.getheader('content-length')
        if length:
            env['CONTENT_LENGTH'] = length
        referer = self.headers.getheader('referer')
        if referer:
            env['HTTP_REFERER'] = referer
        accept = []
        for line in self.headers.getallmatchingheaders('accept'):
            if line[:1] in "\t\n\r ":
                accept.append(line.strip())
            else:
                accept = accept + line[7:].split(',')
        env['HTTP_ACCEPT'] = ','.join(accept)
        ua = self.headers.getheader('user-agent')
        if ua:
            env['HTTP_USER_AGENT'] = ua
        co = filter(None, self.headers.getheaders('cookie'))
        if co:
            env['HTTP_COOKIE'] = ', '.join(co)

        webui.WebUI(self, env).run()
    do_GET = do_POST = run

class StdinoutHandler(RequestHandler):
    def __init__(self):
        # request, client_address, server
        RequestHandler.__init__(self, None, ('',0), None)
    def setup(self):
        self.rfile = sys.stdin
        #import StringIO
        #self.rfile = StringIO.StringIO('GET /pypi HTTP/1.0\r\n\r\n')
        self.wfile = sys.stdout

def main():
    port = 8000
    opts, args =  getopt.getopt(sys.argv[1:], 'ip:',
                                ['interactive', 'port='])
    assert not args
    for opt, val in opts:
        if opt in ('-i', '--interactive'):
            port = None
        elif opt in ('-p', '--port'):
            port = int(val)
    if port:
        httpd = BaseHTTPServer.HTTPServer(('',8000), RequestHandler)
        httpd.serve_forever()
    else:
        StdinoutHandler()

if __name__=='__main__':
    main()
