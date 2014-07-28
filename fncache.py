
import json
from functools import wraps

class RedisLru(object):
    """
    Redis backed LRU cache for functions which return an object which
    can survive json.dumps() and json.loads() intact
    """

    def __init__(self, conn, expires=86400, capacity=5000, prefix="lru", tag=None, arg_index=None, kwarg_name=None, slice_obj=slice(None)):
        """
        conn:      Redis Connection Object
        expires:   Default key expiration time
        capacity:  Approximate Maximum size of caching set
        prefix:    Prefix for all keys in the cache
        tag:       String (formattable optional) to tag keys with for purging
            arg_index/kwarg_name: Choose One, the tag string will be formatted with that argument
        slice_obj: Slice object to cut out un picklable thingz
        """
        self.conn = conn
        self.expires = expires
        self.capacity = capacity
        self.prefix = prefix
        self.tag = tag
        self.arg_index = arg_index
        self.kwarg_name = kwarg_name
        self.slice = slice_obj

    def format_key(self, func_name, tag):
        if tag is not None:
            return ':'.join([self.prefix, tag, func_name])
        return ':'.join([self.prefix, 'tag', func_name])

    def eject(self, func_name):
        count = min((self.capacity / 10) or 1, 1000)
        cache_keys = self.format_key(func_name, '*')
        if self.conn.zcard(cache_keys) >= self.capacity:
            eject = self.conn.zrange(cache_keys, 0, count)
            pipeline = self.conn.pipeline()
            pipeline.zremrangebyrank(cache_keys, 0, count)
            pipeline.hdel(cache_vals, *eject)
            pipeline.execute()

    def get(self, func_name, key, tag):
        value = self.conn.hget(self.format_key(func_name, tag), key)
        if value:
            value = json.loads(value)
        return value

    def add(self, func_name, key, value, tag):
        self.eject(func_name)
        pipeline = self.conn.pipeline()
        pipeline.hset(self.format_key(func_name, tag), key, json.dumps(value))
        pipeline.expire(self.format_key(func_name, tag), self.expires)
        pipeline.execute()
        return value

    def purge(self, tag):
        keys = self.conn.keys(":".join([self.prefix, tag, '*']))
        pipeline = self.conn.pipeline()
        for key in keys:
            pipeline.delete(key)
        pipeline.execute()

    def decorator(self, func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if self.conn is None:
                return func(*args, **kwargs) 
            else:
                try:
                    items = args + tuple(sorted(kwargs.items()))
                    key = json.dumps(items[self.slice])
                    tag = None
                    if self.arg_index is not None and self.kwarg_name is not None:
                        raise ValueError('only one of arg_index or kwarg_name may be specified')
                    if self.arg_index is not None:
                        tag = self.tag % (args[self.arg_index])
                    if self.kwarg_name is not None:
                        tag = self.tag % (kwargs[self.kwarg_name])
                    return self.get(func.__name__, key, tag) or self.add(func.__name__, key, func(*args, **kwargs), tag)
                except redis.exceptions.ConnectionError as conn_fail:
                    return func(*args, **kwargs)
        return wrapper
