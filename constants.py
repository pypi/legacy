
DOMAIN_BLACKLIST = []

try:
    with open('disposable_email_blacklist.conf', 'rU') as f:
        DOMAIN_BLACKLIST = [line.rstrip() for line in blacklist.readlines()]
except Exception:
    pass
    
