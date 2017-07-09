from authomatic.adapters import BaseAdapter
import urlparse
import Cookie
from wsgiref.util import request_uri


class PyPIAdapter(BaseAdapter):


    def __init__(self, env, config, handler, form, return_url=None):
        self.env = env
        self.config = config
        self.handler = handler
        self.form = form
        self.return_url = return_url

    @property
    def params(self):
        return dict(self.form)

    @property
    def url(self):
        return request_uri(self.env, include_query=False)

    @property
    def cookies(self):
        return dict([(k, v.value) for k, v in Cookie.SimpleCookie(self.env.get('HTTP_COOKIE', '')).items()])

    def write(self, value):
        self.handler.set_status('200 OK')
        self.handler.send_header("Content-type", 'text/html')
        self.handler.send_header("Content-length", str(len(value)))
        self.handler.end_headers()
        self.handler.wfile.write(value)

    def set_header(self, key, value):
        self.handler.send_header(key, value)

    def set_status(self, status):
        self.handler.set_status(status)
