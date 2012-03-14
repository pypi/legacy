#!/usr/bin/python
import sys, os
prefix = os.path.dirname(__file__)
sys.path.insert(0, prefix)

import wsgi_app
config_path = os.path.join(prefix, 'testpypi-config.ini')
application = wsgi_app.Application(config_path, debug=True)

if __name__ == '__main__':
    application.test(8000)

