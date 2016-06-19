from authomatic.adapters import BaseAdapter
import urlparse
import Cookie


class PyPIAdapter(BaseAdapter):


    def __init__(self, env, config, handler, form):
        self.env = env
        self.config = config
        self.handler = handler
        self.form = form

    @property
    def params(self):
        return dict(self.form)

    @property
    def url(self):
        parse = urlparse.urlparse(self.config.url)
        return urlparse.urlunparse(parse._replace(path="pypi", query=":action=openid_return"))

    @property
    def cookies(self):
        return dict([(k, v.value) for k, v in Cookie.SimpleCookie(self.env.get('HTTP_COOKIE', '')).items()])

    def write(self, value):
        self.response.end_headers()
        self.handler.wfile.write(value)

    def set_header(self, key, value):
        self.handler.send_header(key, value)

    def set_status(self, status):
        self.handler.set_status(status)
