import xmlrpclib
import traceback
from cStringIO import StringIO

allowed = ('echo','index','search')

def handle_request(webui_obj):
    webui_obj.handler.send_response(200, 'OK')
    webui_obj.handler.send_header('Content-type', 'text/xml')
    webui_obj.handler.send_header('charset', 'UTF-8' );
    webui_obj.handler.end_headers()
    try:
        methodArgs, methodName = xmlrpclib.loads(webui_obj.handler.rfile.read())
        if methodName in allowed:
            response = globals()[methodName](webui_obj.store,*methodArgs)
        else:
            raise KeyError, "Method %r does not exist" % (methodName,)
        if response is None:
            response = ''
        webui_obj.handler.wfile.write( \
            unicode( \
                xmlrpclib.dumps( tuple(response), allow_none=True ),
                errors="ignore" ) )
    except:
        out = StringIO()
        traceback.print_exc(file=out)
        result = xmlrpclib.dumps(xmlrpclib.Fault(1, out.getvalue()))
        webui_obj.handler.wfile.write(result)

def echo(store,*args):
    return args

def index(store,*args):
    spec = { '_pypi_hidden': 'FALSE' } 
    return [row.as_dict() for row in store.query_packages(spec)]

def search(store,*args):
    term = args[0]
    spec = { 'name': term, '_pypi_hidden': 'FALSE' } 
    return [row.as_dict() for row in store.query_packages(spec)]

def info(store, *args):
    name, version = args
    return store.get_package(name, version).as_dict()

def wrapper(payload):
    xmlrpclib.dumps((payload,))
