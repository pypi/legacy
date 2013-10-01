import sys
import xmlrpclib
import traceback
import datetime
import logging
import re
import time
from cStringIO import StringIO
from SimpleXMLRPCServer import SimpleXMLRPCDispatcher
from collections import defaultdict

# local imports
from store import dependency

class RequestHandler(SimpleXMLRPCDispatcher):
    """A request dispatcher for the PyPI XML-RPC API."""

    def __init__(self):
        SimpleXMLRPCDispatcher.__init__(self, True, 'utf-8')
        self.register_function(list_packages)
        self.register_function(package_releases)
        self.register_function(release_urls)
        self.register_function(release_urls, name='package_urls') # Deprecated
        self.register_function(release_data)
        self.register_function(release_data, name='package_data') # Deprecated
        self.register_function(search)
        self.register_function(browse)
        self.register_function(updated_releases)
        self.register_function(changelog)
        self.register_function(changelog_last_serial)
        self.register_function(changelog_since_serial)
        self.register_function(changed_packages)
        self.register_function(post_cheesecake_for_release)
        self.register_function(release_downloads)
        self.register_function(package_roles)
        self.register_function(user_packages)
        self.register_function(package_hosting_mode)
        self.register_function(top_packages)
        self.register_function(list_packages_with_serial)
        self.register_introspection_functions()
        self.register_multicall_functions()

    def __call__(self, webui_obj):
        webui_obj.handler.send_response(200, 'OK')
        webui_obj.handler.send_header('Content-type', 'text/xml')
        webui_obj.handler.send_header('charset', 'UTF-8' )
        webui_obj.handler.end_headers()
        try:
            length = int(webui_obj.env['CONTENT_LENGTH'])
            assert length < 10*1024*1024, 'request content way too big'
            data = webui_obj.handler.rfile.read(length)
            # This should be thread-safe, as the store is really a singleton
            self.store = webui_obj.store
        except Exception, e:
            # report as a fault to caller rather than propogating up to generic
            # exception handler
            response = xmlrpclib.dumps(
                xmlrpclib.Fault(1, repr(e)),
                encoding=self.encoding,
                allow_none=self.allow_none
            )
        else:
            # errors here are handled by _marshaled_dispatch
            response = self._marshaled_dispatch(data)
            # remove non-printable ASCII control codes from the response
            response = re.sub('([\x00-\x08]|[\x0b-\x0c]|[\x0e-\x1f])+', '', response)
        webui_obj.handler.wfile.write(response)

    def _dispatch(self, method, params):
        if not method.startswith('system.'):
            # Add store to all of our own methods
            params = (self.store,)+tuple(params)
        return SimpleXMLRPCDispatcher._dispatch(self, method, params)

    def system_multicall(self, call_list):
        if len(call_list) > 100:
            raise Fault, "multicall too large"
        return SimpleXMLRPCDispatcher.system_multicall(self, call_list)

def package_hosting_mode(store, package_name):
    """Returns the hosting mode for a given package."""
    return store.get_package_hosting_mode(package_name)

def release_downloads(store, package_name, version):
    '''Return download count for given release.'''
    return store.get_release_downloads(package_name, version)

def package_roles(store, package_name):
    '''Return associated users and package roles.'''
    result = store.get_package_roles(package_name)
    return [tuple(fields.values())for fields in result]

def user_packages(store, user):
    '''Return associated packages for user.'''
    result = store.get_user_packages(user)
    return [tuple(fields.values()) for fields in result]

def list_packages(store):
    result = store.get_packages()
    return [row['name'] for row in result]


def list_packages_with_serial(store):
    return store.get_packages_with_serial()

def package_releases(store, package_name, show_hidden=False):
    if show_hidden:
        hidden = None
    else:
        hidden = False
    result = store.get_package_releases(package_name, hidden=hidden)
    return [row['version'] for row in result]

def release_urls(store, package_name, version):
    result = []
    for file in store.list_files(package_name, version):
        info = file.as_dict()
        info['url'] = store.gen_file_url(info['python_version'],
            package_name, info['filename'])
        result.append(info)
    # TODO do something with release_urls when there is something to do
    #info = store.get_package(package_name, version)
    #if info['download_url']:
    #    result.append({'url': info['download_url']})
    return result
package_urls = release_urls     # "deprecated"


def release_data(store, package_name, version):
    info = store.get_package(package_name, version)
    if not info:
        return {}
    info = info.as_dict()
    del info['description_html']
    dependencies = defaultdict(list)
    for kind, specifier in store.get_release_dependencies(package_name, version):
        dependencies[dependency.by_val[kind]].append(specifier)
    info.update(dependencies)
    classifiers = [r[0] for r in store.get_release_classifiers(package_name,
        version)]
    info['classifiers' ] = classifiers
    info['package_url'] = 'http://pypi.python.org/pypi/%s' % package_name
    info['release_url'] = 'http://pypi.python.org/pypi/%s/%s' % (package_name,
        version)
    info['docs_url'] = store.docs_url(package_name)
    info['downloads'] = store.download_counts(package_name)
    return info
package_data = release_data     # "deprecated"

def search(store, spec, operator='and'):
    spec['_pypi_hidden'] = 'FALSE'
    return [row.as_dict() for row in store.query_packages(spec, operator)]

def browse(store, categories):
    if not isinstance(categories, list):
        raise TypeError, "Parameter categories must be a list"
    classifier_ids = store.get_classifier_ids(categories)
    print classifier_ids
    if len(classifier_ids) != len(categories):
        for c in categories:
            if c not in classifier_ids:
                raise ValueError, 'Unknown category "%s"' % c
    ids = classifier_ids.values()
    packages, tally = store.browse(ids)
    return [(name, version) for name, version, desc in packages]

def updated_releases(store, since):
    result = store.updated_releases(since)
    return [(row['name'], row['version']) for row in result]


def changelog_last_serial(store):
    "return the last changelog event's serial"
    return store.changelog_last_serial()

def changelog(store, since, with_ids=False):
    result = []
    for row in store.changelog(since):
        if isinstance(row['submitted_date'], str):
            d = datetime.datetime.strptime(row['submitted_date'],
                '%Y-%m-%d %H:%M:%S').timetuple()
        else:
            d = row['submitted_date'].timetuple()
        t = (row['name'],row['version'], int(time.mktime(d)), row['action'])
        if with_ids:
            t += (row['id'], )
        result.append(t)
    return result

def changelog_since_serial(store, since_serial):
    'return the changes since the nominated event serial (id)'
    result = []
    for row in store.changelog_since_serial(since_serial):
        if isinstance(row['submitted_date'], str):
            d = datetime.datetime.strptime(row['submitted_date'],
                '%Y-%m-%d %H:%M:%S').timetuple()
        else:
            d = row['submitted_date'].timetuple()
        result.append((row['name'],row['version'], int(time.mktime(d)),
            row['action'], row['id']))
    return result

def changed_packages(store, since):
    return store.changed_packages(since)

def post_cheesecake_for_release(store, name, version, score_data, password):
    if password != store.config.cheesecake_password:
        raise ValuError("Bad password.")

    store.save_cheesecake_score(name, version, score_data)
    store.commit()


def top_packages(store, num=None):
    return store.top_packages(num=num)

handle_request = RequestHandler()
