
import os

DOMAIN_BLACKLIST = []

DOMAIN_BLACKLIST_CONF = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                     'disposable_email_blacklist.conf')
try:
    with open(DOMAIN_BLACKLIST_CONF, 'rU') as f:
        DOMAIN_BLACKLIST = [line.rstrip() for line in f.readlines()]
except Exception as e:
    pass
