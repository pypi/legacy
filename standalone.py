#!/usr/bin/python
import config, webui, BaseHTTPServer, urllib, sys, getopt, os

class RequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    config = config.Config(os.path.dirname(__file__)+"/config.ini")
    ssh_user = None

    def set_content_type(self, content_type):
        self.send_header('Content-Type', content_type)

    def run(self):
        if self.path == '/':
            self.send_response(301)
            self.send_header('Location', '/pypi')
            return
        for scriptname in ('/mirrors', '/simple', '/pypi',
                           '/serversig', '/daytime', '/id'):
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
        if self.ssh_user:
            # ignore authorization headers if this is a SSH client
            authorization = None
            env['SSH_USER'] = self.ssh_user
        else:
            authorization = self.headers.getheader("authorization")
        if authorization:
            env['HTTP_CGI_AUTHORIZATION'] = authorization
            authorization = authorization.split()
            if len(authorization) == 2:
                import base64, binascii
                env['AUTH_TYPE'] = authorization[0]
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
        ac = self.headers.getheader('accept-encoding')
        if ac:
            env['HTTP_ACCEPT_ENCODING'] = ac

        webui.WebUI(self, env).run()
    do_GET = do_POST = run

class StdinoutHandler(RequestHandler):
    def __init__(self, remote_user):
        self.ssh_user = remote_user
        try:
            host,port,_ = os.environ['SSH_CLIENT'].split()
        except KeyError:
            host = port = ''
        # request, client_address, server
        RequestHandler.__init__(self, None, (host, port), None)
    def setup(self):
        self.rfile = sys.stdin
        #import StringIO
        #self.rfile = StringIO.StringIO('GET /pypi HTTP/1.0\r\n\r\n')
        self.wfile = sys.stdout

def main():
    os.umask(002) # make directories group-writable
    port = 8000
    remote_user = None
    opts, args =  getopt.getopt(sys.argv[1:], 'ir:p:',
                                ['interactive', 'remote-user=', 'port='])
    assert not args
    for opt, val in opts:
        if opt in ('-i', '--interactive'):
            port = None
        elif opt in ('-r','--remote-user'):
            port = None # implies -i
            remote_user = val
        elif opt in ('-p', '--port'):
            port = int(val)
    if port:
        httpd = BaseHTTPServer.HTTPServer(('',port), RequestHandler)
        httpd.serve_forever()
    else:
        StdinoutHandler(remote_user)

if __name__=='__main__':
    main()
