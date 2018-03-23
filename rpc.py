import os
import sys
import xmlrpclib
import traceback
import datetime
import logging
import re
import time
import json
from cStringIO import StringIO
from SimpleXMLRPCServer import SimpleXMLRPCDispatcher
from collections import defaultdict
from contextlib import contextmanager

from perfmetrics import metric
from perfmetrics import metricmethod
from perfmetrics import set_statsd_client
from perfmetrics import statsd_client

import redis

# local imports
import config

from store import dependency
from fncache import RedisLru

from dogadapter import dogstatsd

root = os.path.dirname(os.path.abspath(__file__))
conf = config.Config(os.path.join(root, "config.ini"))

redis_kwargs = {
    'socket_connect_timeout': 0.1,
    'socket_timeout': 0.05,
}

if conf.cache_redis_url is None:
    cache_redis = None
else:
    cache_redis = redis.StrictRedis.from_url(conf.cache_redis_url, **redis_kwargs)

# Note: slice object is to cut off the instance of Store that would be passed along
package_tag_lru = RedisLru(cache_redis, expires=86400, tag="pkg~%s", arg_index=1, slice_obj=slice(1, None))
cache_by_pkg = package_tag_lru.decorator

if conf.xmlrpc_redis_url is None:
    xmlrpc_redis = None
else:
    xmlrpc_redis = redis.StrictRedis.from_url(conf.xmlrpc_redis_url, **redis_kwargs)

STATSD_URI = "statsd://127.0.0.1:8125?prefix=%s" % (conf.database_name)
set_statsd_client(STATSD_URI)
statsd_reporter = statsd_client()

def log_xmlrpc_request(remote_addr, user_agent, data):
    if conf.xmlrpc_request_log_file:
        try:
            with open(conf.xmlrpc_request_log_file, 'a') as f:
                params, method = xmlrpclib.loads(data)
                dogstatsd.increment('xmlrpc.request', tags=['method:{}'.format(method)])
                record = json.dumps({
                    'timestamp': datetime.datetime.utcnow().isoformat(),
                    'remote_addr': remote_addr,
                    'user_agent': user_agent,
                    'method': method,
                    'params': params,
                    'type': 'request',
                })
                f.write(record + '\n')
        except Exception:
            pass


def log_xmlrpc_response(remote_addr, user_agent, data, response_size):
    if conf.xmlrpc_request_log_file:
        try:
            with open(conf.xmlrpc_request_log_file, 'a') as f:
                params, method = xmlrpclib.loads(data)
                dogstatsd.increment('xmlrpc.response', tags=['method:{}'.format(method)])
                dogstatsd.histogram('xmlrpc.response.size', response_size, tags=['method:{}'.format(method)])
                record = json.dumps({
                    'timestamp': datetime.datetime.utcnow().isoformat(),
                    'remote_addr': remote_addr,
                    'user_agent': user_agent,
                    'method': method,
                    'params': params,
                    'response_size': response_size,
                    'type': 'response',
                })
                f.write(record + '\n')
        except Exception:
            pass


def log_xmlrpc_throttle(remote_addr, enforced):
    if conf.xmlrpc_request_log_file:
        try:
            with open(conf.xmlrpc_request_log_file, 'a') as f:
                dogstatsd.increment('xmlrpc.throttled', tags=['remote_addr:{}'.format(remote_addr), 'enforced:{}'.format(enforced)])
                record = json.dumps({
                    'timestamp': datetime.datetime.utcnow().isoformat(),
                    'remote_addr': remote_addr,
                    'method': 'throttled',
                    'throttle_enforced': enforced,
                })
                f.write(record + '\n')
        except Exception:
            pass


@contextmanager
def throttle_concurrent(remote_addr):
    throttled = False
    try:
        if xmlrpc_redis:
            dogstatsd.increment('xmlrpc.rate-limit.invoke')
            statsd_reporter.incr('rpc-rl.invoke')
            pipeline = xmlrpc_redis.pipeline()
            pipeline.incr(remote_addr)
            pipeline.expire(remote_addr, 60)
            current = pipeline.execute()[0]
            if current >= conf.xmlrpc_concurrent_requests:
                dogstatsd.increment('xmlrpc.rate-limit.over')
                statsd_reporter.incr('rpc-rl.over')
                log_xmlrpc_throttle(remote_addr, conf.xmlrpc_enforce)
                if conf.xmlrpc_enforce:
                    dogstatsd.increment('xmlrpc.rate-limit.enforce')
                    statsd_reporter.incr('rpc-rl.enforce')
                    throttled = True
    except Exception:
        dogstatsd.increment('xmlrpc.rate-limit.context.before.error')
        statsd_reporter.incr('rpc-rl.context.before.error')
        pass
    yield throttled
    try:
        if xmlrpc_redis:
            xmlrpc_redis.decr(remote_addr)
    except Exception:
        dogstatsd.increment('xmlrpc.rate-limit.context.after.error')
        statsd_reporter.incr('rpc-rl.context.after.error')
        pass

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

    @dogstatsd.timed('xmlrpc.call')
    @metricmethod
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
            user_agent = webui_obj.env.get('HTTP_USER_AGENT', None)
            log_xmlrpc_request(webui_obj.remote_addr, user_agent, data)
            with throttle_concurrent(webui_obj.remote_addr) as is_throttled:
                if is_throttled:
                    response = xmlrpclib.dumps(
                        xmlrpclib.Fault(429, 'max concurrent requests exceeded'),
                        encoding=self.encoding,
                        allow_none=self.allow_none
                    )
                else:
                    # errors here are handled by _marshaled_dispatch
                    response = self._marshaled_dispatch(data)
                    # remove non-printable ASCII control codes from the response
                    response = re.sub('([\x00-\x08]|[\x0b-\x0c]|[\x0e-\x1f])+', '', response)
            log_xmlrpc_response(webui_obj.remote_addr, user_agent, data, len(response))
        webui_obj.handler.wfile.write(response)

    @dogstatsd.timed('xmlrpc.dispatch')
    @metricmethod
    def _dispatch(self, method, params):
        if not method.startswith('system.'):
            # Add store to all of our own methods
            params = (self.store,)+tuple(params)
        return SimpleXMLRPCDispatcher._dispatch(self, method, params)

    @dogstatsd.timed('xmlrpc.multicall')
    @metricmethod
    def system_multicall(self, call_list):
        if len(call_list) > 100:
            raise Fault, "multicall too large"
        return SimpleXMLRPCDispatcher.system_multicall(self, call_list)

@dogstatsd.timed('xmlrpc.function', tags=['function:package_hosting_mode'])
@metric
def package_hosting_mode(store, package_name):
    """Returns the hosting mode for a given package."""
    return store.get_package_hosting_mode(package_name)

@dogstatsd.timed('xmlrpc.function', tags=['function:release_downloads'])
@metric
@cache_by_pkg
def release_downloads(store, package_name, version):
    '''Return download count for given release.'''
    return store.get_release_downloads(package_name, version)

@dogstatsd.timed('xmlrpc.function', tags=['function:package_roles'])
@metric
@cache_by_pkg
def package_roles(store, package_name):
    '''Return associated users and package roles.'''
    result = store.get_package_roles(package_name)
    return [tuple(fields.values())for fields in result]

@dogstatsd.timed('xmlrpc.function', tags=['function:user_packages'])
@metric
def user_packages(store, user):
    '''Return associated packages for user.'''
    result = store.get_user_packages(user)
    return [tuple(fields.values()) for fields in result]

@dogstatsd.timed('xmlrpc.function', tags=['function:list_packages'])
@metric
def list_packages(store):
    result = store.get_packages()
    return [row['name'] for row in result]

@dogstatsd.timed('xmlrpc.function', tags=['function:list_packages_with_serial'])
@metric
def list_packages_with_serial(store):
    return store.get_packages_with_serial()

@dogstatsd.timed('xmlrpc.function', tags=['function:package_releases'])
@metric
@cache_by_pkg
def package_releases(store, package_name, show_hidden=False):
    if show_hidden:
        hidden = None
    else:
        hidden = False
    result = store.get_package_releases(package_name, hidden=hidden)
    return [row['version'] for row in result]

@dogstatsd.timed('xmlrpc.function', tags=['function:release_urls'])
@metric
def release_urls(store, package_name, version):
    result = []
    for file in store.list_files(package_name, version):
        info = file.as_dict()
        info['url'] = store.gen_file_url(info['python_version'],
            package_name, info['filename'], path=info['path'])
        info['digests'] = {'md5': file['md5_digest'], 'sha256': file['sha256_digest']}
        result.append(info)
    # TODO do something with release_urls when there is something to do
    #info = store.get_package(package_name, version)
    #if info['download_url']:
    #    result.append({'url': info['download_url']})
    return result
package_urls = release_urls     # "deprecated"


@dogstatsd.timed('xmlrpc.function', tags=['function:release_data'])
@metric
@cache_by_pkg
def release_data(store, package_name, version):
    info = store.get_package(package_name, version)
    if not info:
        return {}
    info = info.as_dict()
    if "description_html" in info:
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
    try:
        info['downloads'] = store.download_counts(package_name)
    except redis.exceptions.ConnectionError as conn_fail:
        info['downloads'] = {'last_month': 0, 'last_week': 0, 'last_day': 0}
    return info
package_data = release_data     # "deprecated"

@dogstatsd.timed('xmlrpc.function', tags=['function:search'])
@metric
def search(store, spec, operator='and'):
    spec['_pypi_hidden'] = 'FALSE'
    return [row.as_dict() for row in store.search_packages(spec, operator)]

@dogstatsd.timed('xmlrpc.function', tags=['function:browse'])
@metric
def browse(store, categories):
    if not isinstance(categories, list):
        raise TypeError, "Parameter categories must be a list"
    classifier_ids = store.get_classifier_ids(categories)
    if len(classifier_ids) != len(categories):
        for c in categories:
            if c not in classifier_ids:
                raise ValueError, 'Unknown category "%s"' % c
    ids = classifier_ids.values()
    packages, tally = store.browse(ids)
    return [(name, version) for name, version, desc in packages]

@dogstatsd.timed('xmlrpc.function', tags=['function:updated_releases'])
@metric
def updated_releases(store, since):
    result = store.updated_releases(since)
    return [(row['name'], row['version']) for row in result]


@dogstatsd.timed('xmlrpc.function', tags=['function:changelog_last_serial'])
@metric
def changelog_last_serial(store):
    "return the last changelog event's serial"
    return store.changelog_last_serial()

@dogstatsd.timed('xmlrpc.function', tags=['function:changelog'])
@metric
def changelog(store, since, with_ids=False):
    result = []
    for row in store.changelog(since, full=False):
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

@dogstatsd.timed('xmlrpc.function', tags=['function:changelog_since_serial'])
@metric
def changelog_since_serial(store, since_serial):
    'return the changes since the nominated event serial (id)'
    result = []
    for row in store.changelog_since_serial(since_serial, full=False):
        if isinstance(row['submitted_date'], str):
            d = datetime.datetime.strptime(row['submitted_date'],
                '%Y-%m-%d %H:%M:%S').timetuple()
        else:
            d = row['submitted_date'].timetuple()
        result.append((row['name'],row['version'], int(time.mktime(d)),
            row['action'], row['id']))
    return result

@dogstatsd.timed('xmlrpc.function', tags=['function:changed_packages'])
@metric
def changed_packages(store, since):
    return store.changed_packages(since)

@dogstatsd.timed('xmlrpc.function', tags=['function:post_cheesecake_for_release'])
@metric
def post_cheesecake_for_release(store, name, version, score_data, password):
    if password != store.config.cheesecake_password:
        raise ValuError("Bad password.")

    store.save_cheesecake_score(name, version, score_data)
    store.commit()


@dogstatsd.timed('xmlrpc.function', tags=['function:top_packages'])
@metric
def top_packages(store, num=None):
    return store.top_packages(num=num)

handle_request = RequestHandler()
