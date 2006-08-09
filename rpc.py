import xmlrpclib
import traceback
from cStringIO import StringIO

allowed = ('package_releases', 'package_urls', 'package_data',
    'search', 'list_packages', 'release_urls', 'release_data',
    'updated_releases')

def handle_request(webui_obj):
    webui_obj.handler.send_response(200, 'OK')
    webui_obj.handler.send_header('Content-type', 'text/xml')
    webui_obj.handler.send_header('charset', 'UTF-8' );
    webui_obj.handler.end_headers()
    try:
        methodArgs, methodName = xmlrpclib.loads(webui_obj.handler.rfile.read())
        if methodName in allowed:
            response = globals()[methodName](webui_obj.store, *methodArgs)
        else:
            raise KeyError, "Method %r does not exist" % (methodName,)
        if response is None:
            response = ''
        # xmlrpclib.dumps encodes Unicode as UTF-8
        xml = xmlrpclib.dumps((response,), allow_none=True)
        webui_obj.handler.wfile.write(xml)
    except:
        out = StringIO()
        traceback.print_exc(file=out)
        result = xmlrpclib.dumps(xmlrpclib.Fault(1, out.getvalue()))
        webui_obj.handler.wfile.write(result)

def list_packages(store):
    result = store.get_packages()
    return [row['name'] for row in result]

def package_releases(store, package_name):
    result = store.get_package_releases(package_name, hidden=False)
    return [row['version'] for row in result]

def release_urls(store, package_name, version):
    result = []
    for file in store.list_files(package_name, version):
        url = store.gen_file_url(file['python_version'],
            package_name, file['filename'])
        result.append({'url': url, 'packagetype': file['packagetype']})
    # TODO do something with release_urls when there is something to do
    #info = store.get_package(package_name, version)
    #if info['download_url']:
    #    result.append({'url': info['download_url']})
    return result
package_urls = release_urls     # "deprecated"

def release_data(store, package_name, version):
    info = store.get_package(package_name, version).as_dict()
    del info['description_html']
    classifiers = [r[0] for r in store.get_release_classifiers(package_name,
        version)]
    info['classifiers' ] = classifiers
    return info
package_data = release_data     # "deprecated"

def search(store, spec, operator='and'):
    spec['_pypi_hidden'] = 'FALSE'
    return [row.as_dict() for row in store.query_packages(spec, operator)]

def updated_releases(store, since):
    result = store.updated_releases(since)
    return [(row['name'], row['version']) for row in result]
