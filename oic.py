from authomatic.adapters import BaseAdapter


class PyPIAdapter(BaseAdapter):


    def __init__(self, config, handler, form):
        self.config = config
        self.handler = handler
        self.form = form

    @property
    def params(self):
        return dict(self.form)

    @property
    def url(self):
        return self.config.url

    @property
    def cookies(self):
        return {}

    def write(self, value):
        self.handler.wfile.write(value)

    def set_header(self, key, value):
        self.handler.send_header(key, value)

    def set_status(self, status):
        self.handler.status = status
