import os
import urlparse

import redis
import requests

from fncache import RedisLru

def purge_redis_cache(cache_redis_url, tags):
    cache_redis = redis.StrictRedis.from_url(cache_redis_url)
    lru_cache = RedisLru(cache_redis) 

    all_tags = set(tags)
    for tag in set(all_tags):
        print tag
        lru_cache.purge(tag)

def purge_fastly_tags(domain, api_key, service_id, tags):
    session = requests.session()
    headers = {"Fastly-Key": api_key, "Accept": "application/json"}

    all_tags = set(tags)
    purges = {}

    for tag in set(all_tags):
        # Build the URL
        url_path = "/service/%s/purge/%s" % (service_id, tag)
        url = urlparse.urljoin(domain, url_path)

        # Issue the Purge
        resp = session.post(url, headers=headers)
        resp.raise_for_status()

        # Store the Purge ID so we can track it later
        purges[tag] = resp.json()["id"]

    # for tag, purge_id in purges.iteritems():
    #     # Ensure that the purge completed successfully
    #     url = urlparse.urljoin(domain, "/purge")
    #     status = session.get(url, params={"id": purge_id})
    #     status.raise_for_status()

    #     # If the purge completely successfully remove the tag from
    #     #   our list.
    #     if status.json().get("results", {}).get("complete", None):
    #         all_tags.remove(tag)

import config
import store

from zope.pagetemplate.pagetemplatefile import PageTemplateFile


class PyPiPageTemplate(PageTemplateFile):
    def pt_getContext(self, args=(), options={}, **kw):
        """Add our data into ZPT's defaults"""
        rval = PageTemplateFile.pt_getContext(self, args=args)
        options.update(rval)
        return options

def rss_regen():
    root = os.path.dirname(os.path.abspath(__file__))
    conf = config.Config(os.path.join(root, "config.ini"))
    template_dir = os.path.join(root, 'templates')

    if conf.cache_redis_url:
        cache_redis = redis.StrictRedis.from_url(conf.cache_redis_url)
    else:
        return True

    (protocol, machine, path, x, x, x) = urlparse.urlparse(conf.url)

    context = {}
    context['store'] = store.Store(conf)
    context['url_machine'] = '%s://%s'%(protocol, machine)
    context['url_path'] = path
    context['test'] = ''
    if 'testpypi' in conf.url:
        context['test'] = 'Test '

    # generate the releases RSS
    template = PyPiPageTemplate('rss.xml', template_dir)
    content = template(**context)
    cache_redis.set('rss~main', content)

    # generate the packages RSS
    template = PyPiPageTemplate('packages-rss.xml', template_dir)
    content = template(**context)
    cache_redis.set('rss~pkgs', content)
