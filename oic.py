from authomatic.adapters import BaseAdapter
import urlparse
import Cookie


class PyPIAdapter(BaseAdapter):


    def __init__(self, env, config, handler, form):
        self.env = env
        self.config = config
        self.handler = handler
        self.form = form
        print self.config
        print self.handler
        print self.form
        print 'initialized'

    @property
    def params(self):
        print 'called params'
        print self.form
        return dict(self.form)

    @property
    def url(self):
        print 'called url'
        print self.config.url
        parse = urlparse.urlparse(self.config.url)
        return urlparse.urlunparse(parse._replace(path="google_login"))

    @property
    def cookies(self):
        print 'called cookies'
        return Cookie.SimpleCookie(self.env.get('HTTP_COOKIE', ''))

    def write(self, value):
        print 'called write'
        print value
        self.response.end_headers()
        self.handler.wfile.write(value)

    def set_header(self, key, value):
        print 'called set header'
        print (key, value)
        self.handler.send_header(key, value)

    def set_status(self, status):
        print 'called set status'
        print status
        self.handler.set_status(status)
