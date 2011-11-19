# -*- coding: utf-8 -*-
# OpenID relying party library
# Copyright Martin v. Löwis, 2009
# Licensed under the Academic Free License, version 3

# This library implements OpenID Authentication 2.0,
# in the role of a relying party

import urlparse, urllib, httplib, time, cgi, HTMLParser
import cStringIO, base64, hmac, hashlib, datetime, re, random
import itertools, cPickle, sys

try:
    from xml.etree import ElementTree
except ImportError:
    from elementtree import ElementTree

# Don't use urllib2, since it breaks in 2.5
# for https://login.launchpad.net//+xrds

# Don't use urllib, since it sometimes selects HTTP/1.1 (e.g. in PyPI)
# and then fails to parse chunked responses.

# 3.x portability

if sys.version_info < (3,):
    def b(s):
        return s
    # Convert byte to integer
    b2i = ord
    def bytes_from_ints(L):
        return ''.join([chr(i) for i in L])
else:
    def b(s):
        return s.encode('latin-1')
    def b2i(char):
        # 3.x: bytes are already sequences of integers
        return char
    bytes_from_ints = bytes

class NotAuthenticated(Exception):
    CONNECTION_REFUSED = 1
    DIRECT_VERIFICATION_FAILED = 2
    CANCELLED = 3
    UNSUPPORTED_VERSION = 4
    UNEXPECTED_MODE = 5
    CLAIMED_ID_MISSING = 6
    DISCOVERY_FAILED = 7
    INCONSISTENT_IDS = 8
    REPLAY_ATTACK = 9
    MISSING_NONCE = 10
    msgs = {
        CONNECTION_REFUSED : 'OP refuses connection with status %d',
        DIRECT_VERIFICATION_FAILED : 'OP doesn\'t assert that the signature of the verification request is valid',
        CANCELLED : 'OP did not authenticate user (cancelled)',
        UNSUPPORTED_VERSION : 'Unsupported OpenID version',
        UNEXPECTED_MODE : 'Unexpected mode %s',
        CLAIMED_ID_MISSING : 'Cannot determine claimed ID',
        DISCOVERY_FAILED : 'Claimed ID %s cannot be rediscovered',
        INCONSISTENT_IDS : 'Discovered and asserted endpoints differ',
        REPLAY_ATTACK : 'Replay attack detected',
        MISSING_NONCE : 'Nonce missing in OpenID 2 response',
        }

    def __init__(self, errno, *args):
        msg = self.msgs[errno]
        if args:
            msg %= args
        self.errno = errno
        Exception.__init__(self, msg, errno, *args)

    def __str__(self):
        return self.args[0]

def normalize_uri(uri):
    """Normalize an uri according to OpenID section 7.2. Return a pair
    type,value, where type can be either 'xri' or 'uri'."""
    
    # 7.2 Normalization
    if uri.startswith('xri://'):
        uri = uri[6:]
    if uri[0] in ("=", "@", "+", "$", "!", ")"):
        return 'xri', uri
    if not uri.startswith('http'):
        uri = 'http://' + uri
    # RFC 3986, section 6

    # 6.2.2.1 case normalization
    parts = urlparse.urlparse(uri) # already lower-cases scheme
    if '@' in parts[1]: #netloc
        userinfo,hostname = parts[1].rsplit('@', 1)
    else:
        userinfo,hostname = None,parts[1]
    if ':' in hostname:
        host,port = hostname.rsplit(':', 1)
        if ']' in port:
            # IPv6
            host,port = hostname,None
    else:
        host,port = hostname,None
    netloc = hostname = host.lower()
    if port:
        netloc = hostname = host+':'+port
    if userinfo:
        netloc = userinfo + '@' + hostname
    parts = list(parts)
    parts[1] = netloc
    uri = urlparse.urlunparse(parts)

    # 6.2.2.2. normalize case in % escapes
    # XXX should restrict search to parts that can be pct-encoded
    for match in re.findall('%[0-9a-fA-F][0-9a-fA-F]', uri):
        m2 = match.upper()
        if m2 != match:
            uri = uri.replace(match, m2)

    # 6.2.2.3 remove dot segments
    parts = urlparse.urlparse(uri)
    path = parts[2] #path
    newpath = ''
    while path:
        if path.startswith('../'):
            path = path[3:]
        elif path.startswith('./'):
            path = path[2:]
        elif path.startswith('/./'):
            newpath += '/'; path = path[3:]
        elif path == '/.':
            newpath += '/'; path = ''
        elif path.startswith('/../'):
            newpath = newpath.rsplit('/', 1)[0]
            path = path[3:] # leave /
        elif path == '/..':
            newpath = newpath.rsplit('/', 1)[0]
            path = '/'
        elif path == '.' or path=='..':
            path = ''
        else:
            pos = path.find('/', 1)
            if pos == -1:
                pos = len(path)
            newpath += path[:pos]
            path = path[pos:]
    parts = list(parts)
    parts[2] = newpath
    uri = urlparse.urlunparse(parts)

    # 6.2.3 scheme based normalization

    parts = urlparse.urlparse(uri)    
    netloc = parts[1]
    if netloc.endswith(':'):
        netloc = netloc[:-1]
    elif parts[0] == 'http' and netloc.endswith(':80'):
        netloc = netloc[:-3]
    elif parts[0] == 'https' and netloc.endswith(':443'):
        netloc = netloc[:-4]
    # other default ports not considered here

    path = parts[2]
    if parts[0] in ('http', 'https') and parts[2]=='':
        path = '/'

    # 6.2.5 protocol-based normalization not done, as it
    # is not appropriate to resolve the URL just for normalization
    # it seems like a bug in the OpenID spec that it doesn't specify
    # which normalizations exactly should be performed

    parts = list(parts)
    parts[1] = netloc
    parts[2] = path
    return 'uri', urlparse.urlunparse(parts)


def parse_response(s):
    '''Parse a key-value form (OpenID section 4.1.1) into a dictionary'''
    res = {}
    for line in s.decode('utf-8').splitlines():
        k,v = line.split(':', 1)
        res[k] = v
    return res

class OpenIDParser(HTMLParser.HTMLParser):
    def __init__(self):
        HTMLParser.HTMLParser.__init__(self)
        self.links = {}
        self.xrds_location=None

    def handle_starttag(self, tag, attrs):
        if tag == 'link':
            attrs = dict(attrs)
            try:
                self.links[attrs['rel']] = attrs['href']
            except KeyError:
                pass
        elif tag == 'meta':
            attrs = dict(attrs)
            # Yadis 6.2.5 option 1: meta tag
            if attrs.get('http-equiv','').lower() == 'x-xrds-location':
                self.xrds_location = attrs['content']

def _extract_services(doc):
    for svc in doc.findall(".//{xri://$xrd*($v*2.0)}Service"):
        services = [x.text for x in svc.findall("{xri://$xrd*($v*2.0)}Type")]
        if 'http://specs.openid.net/auth/2.0/server' in services:
            # 7.3.2.1.1 OP Identifier Element
            uri = svc.find("{xri://$xrd*($v*2.0)}URI")
            if uri is not None:
                op_local = None
                op_endpoint = uri.text
                break
        elif 'http://specs.openid.net/auth/2.0/signon' in services:
            # 7.3.2.1.2.  Claimed Identifier Element
            op_local = svc.find("{xri://$xrd*($v*2.0)}LocalID")
            if op_local is not None:
                op_local = op_local.text
            uri = svc.find("{xri://$xrd*($v*2.0)}URI")
            if uri is not None:
                op_endpoint = uri.text
                break
        elif 'http://openid.net/server/1.0' in services or \
                'http://openid.net/server/1.1' in services or \
                'http://openid.net/signon/1.0' in services or \
                'http://openid.net/signon/1.1' in services:
            # 14.2.1 says we also need to check for the 1.x types;
            # XXX should check 1.x only if no 2.0 service is found
            op_local = svc.find("{http://openid.net/xmlns/1.0}Delegate")
            if op_local is not None:
                op_local = op_local.text
            uri = svc.find("{xri://$xrd*($v*2.0)}URI")
            if uri is not None:
                op_endpoint = uri.text
                break
    else:
        return None # No OpenID 2.0 service found
    return services, op_endpoint, op_local

def discover(url):
    '''Perform service discovery on the OP URL.
    Return list of service types, and the auth/2.0 URL,
    or None if discovery fails.'''
    scheme, netloc, path, query, fragment = urlparse.urlsplit(url)
    assert not fragment
    if scheme == 'https':
        conn = httplib.HTTPSConnection(netloc)
    elif scheme == 'http':
        conn = httplib.HTTPConnection(netloc)
    else:
        raise ValueError, "Unsupported scheme "+scheme
    # conn.set_debuglevel(1)
    if query:
        path += '?'+query
    try:
        conn.connect()
    except:
        # DNS or TCP error
        return None
    # httplib in 2.5 incorrectly sends https port in Host
    # header even if it is 443
    conn.putrequest("GET", path, skip_host=1)
    conn.putheader('Host', netloc)
    conn.putheader('Accept', "text/html; q=0.3, "+
                   "application/xhtml+xml; q=0.5, "+
                   "application/xrds+xml")
    conn.endheaders()

    res = conn.getresponse()
    data = res.read()
    conn.close()

    if res.status in (301, 302, 303, 307):
        return discover(res.msg.get('location'))

    if sys.version_info < (3,0):
        content_type = res.msg.gettype()
    else:
        content_type = res.msg.get_content_type()

    # Yadis 6.2.5 option 2 and 3: header includes x-xrds-location
    xrds_loc = res.msg.get('x-xrds-location')
    if xrds_loc and content_type != 'application/xrds+xml':
        return discover(xrds_loc)

    if content_type in ('text/html', 'application/xhtml+xml'):
        parser = OpenIDParser()
        parser.feed(data.decode('latin-1'))
        parser.close()
        # Yadis 6.2.5 option 1: meta tag
        if parser.xrds_location:
            return discover(parser.xrds_location)
        # OpenID 7.3.3: attempt html based discovery
        op_endpoint = parser.links.get('openid2.provider')
        if op_endpoint:
            op_local = parser.links.get('openid2.local_id')
            return ['http://specs.openid.net/auth/2.0/signon'], op_endpoint, op_local
        # 14.2.1: 1.1 compatibility
        op_endpoint = parser.links.get('openid.server')
        if op_endpoint:
            op_local = parser.links.get('openid.delegate')
            return ['http://openid.net/signon/1.1'], op_endpoint, op_local
        # Discovery failed
        return None

    elif content_type == 'application/xrds+xml':
        # Yadis 6.2.5 option 4
        doc = ElementTree.fromstring(data)
        return _extract_services(doc)
    else:
        # unknown content type
        return None
    return services, op_endpoint, op_local

def resolve_xri(xri, proxy='xri.net'):
    '''Perform XRI resolution of xri using a proxy resolver.
    Return canonical ID, services, op endpoint, op local;
    return None if an error occurred'''
    xri = urllib.quote(xri, safe='=@*!+()')
    # Ask explicitly for the specific service types, to
    # avoid having to identify the correct XRD element in
    # case the identifier is hierarchical
    for stype in ('http://specs.openid.net/auth/2.0/signon',
                  'http://openid.net/signon/1.0'):
        conn = httplib.HTTPConnection(proxy)
        try:
            conn.connect()
        except:
            # DNS or TCP error
            return None
        conn.putrequest("GET", '/'+xri+'?_xrd_r=application/xrd+xml'
                        +'&_xrd_t='+stype)
        conn.putheader('Connection', 'Keep-Alive')
        conn.endheaders()
        res = conn.getresponse()
        data = res.read()
        doc = ElementTree.fromstring(data)
        res = _extract_services(doc)
        conn.close()
        if res is not None:
            break
    else:
        # No OpenID service found
        return None
    services, op_endpoint, op_local = res
    canonical_id = doc.find(".//{xri://$xrd*($v*2.0)}CanonicalID")
    if canonical_id is None:
        return None
    return canonical_id.text, services, op_endpoint, op_local

def is_compat_1x(services):
    for uri in ('http://specs.openid.net/auth/2.0/signon',
                'http://specs.openid.net/auth/2.0/server'):
        if uri in services:
            return False
    for uri in ('http://openid.net/signon/1.0',
                'http://openid.net/signon/1.1',
                'http://openid.net/server/1.0',
                'http://openid.net/server/1.1'):
        if uri in services:
            return True
    raise ValueError, "Neither 1.x nor 2.0 service found"

def is_op_endpoint(services):
    for uri in ('http://specs.openid.net/auth/2.0/server',
                'http://openid.net/server/1.0',
                'http://openid.net/server/1.1'):
        if uri in services:
            return True
    return False
is_op_identifier = is_op_endpoint

# 4.1.3: Binary two's complement
def btwoc(l):
    res = cPickle.dumps(l, 2)
    # Pickle result: proto 2, long1 (integer < 256 bytes)
    # number of bytes, little-endian integer, stop
    assert res[:3] == b('\x80\x02\x8a')
    # btwoc ought to produce the shortest representation in two's
    # complement. Fortunately, pickle already does that.
    return res[3+b2i(res[3]):3:-1]

def unbtwoc(B):
    return cPickle.loads(b('\x80\x02\x8a')+bytes_from_ints([len(B)])+B[::-1]+(b'.'))

# Appendix B; DH default prime
dh_prime = """
DCF93A0B883972EC0E19989AC5A2CE310E1D37717E8D9571BB7623731866E61E
F75A2E27898B057F9891C2E27A639C3F29B60814581CD3B2CA3986D268370557
7D45C2E7E52DC81C7A171876E5CEA74B1448BFDFAF18828EFD2519F14E45E382
6634AF1949E5B535CC829A483B8A76223E5D490A257F05BDFF16F2FB22C583AB
"""
dh_prime = long("".join(dh_prime.split()), 16)

def string_xor(s1, s2):
    res = []
    for c1, c2 in itertools.izip(s1, s2):
        res.append(b2i(c1) ^ b2i(c2))
    return bytes_from_ints(res)

def associate(services, url):
    '''Create an association (OpenID section 8) between RP and OP.
    Return response as a dictionary.'''
    data = {
        'openid.ns':"http://specs.openid.net/auth/2.0",
        'openid.mode':"associate",
        'openid.assoc_type':"HMAC-SHA1",
        'openid.session_type':"no-encryption",
        }
    if url.startswith('http:'):
        # Use DH exchange
        data['openid.session_type'] = "DH-SHA1"
        # Private key: random number between 1 and dh_prime-1
        priv = random.randrange(1, dh_prime-1)
        # Public key: 2^priv mod prime
        pubkey = pow(2L, priv, dh_prime)
        dh_public_base64 = base64.b64encode(btwoc(pubkey))
        # No need to send key and generator
        data['openid.dh_consumer_public'] = dh_public_base64
    if is_compat_1x(services):
        # 14.2.1: clear session_type in 1.1 compatibility mode
        if data['openid.session_type'] == "no-encryption":
            data['openid.session_type'] = ''
        del data['openid.ns']
    res = urllib.urlopen(url, b(urllib.urlencode(data)))
    if res.getcode() != 200:
        raise ValueError, "OpenID provider refuses connection with status %d" % res.getcode()
    data = parse_response(res.read())
    if 'error' in data:
        raise ValueError, "associate failed: "+data['error']
    if url.startswith('http:'):
        enc_mac_key = b(data.get('enc_mac_key'))
        if not enc_mac_key:
            raise ValueError, "Provider protocol error: not using DH-SHA1"
        enc_mac_key = base64.b64decode(enc_mac_key)
        dh_server_public = unbtwoc(base64.b64decode(b(data['dh_server_public'])))
        # shared secret: sha1(2^(server_priv*priv) mod prime) xor enc_mac_key
        shared_secret = btwoc(pow(dh_server_public, priv, dh_prime))
        shared_secret = hashlib.sha1(shared_secret).digest()
        if len(shared_secret) != len(enc_mac_key):
            raise ValueError, "incorrect DH key size"
        # Fake mac_key result
        data['mac_key'] = b(base64.b64encode(string_xor(enc_mac_key, shared_secret)))
    return data

class _AX:
    def __init__(self):
        self.__dict__['_reverse'] = {}
    def __setattr__(self, name, value):
        self.__dict__[name] = value
        self._reverse[value] = name
    def lookup(self, value):
        try:
            return self._reverse[value]
        except KeyError:
            return 'a%d' % (hash(value) % 1000000000)

AX = _AX()
AX.nickname  = "http://axschema.org/namePerson/friendly"
AX.email     = "http://axschema.org/contact/email"
AX.fullname  = "http://axschema.org/namePerson"
AX.dob       = "http://axschema.org/birthDate"
AX.gender    = "http://axschema.org/person/gender"
AX.postcode  = "http://axschema.org/contact/postalCode/home"
AX.country   = "http://axschema.org/contact/country/home"
AX.language  = "http://axschema.org/pref/language"
AX.timezone  = "http://axschema.org/pref/timezone"
AX.first     = "http://axschema.org/namePerson/first"
AX.last      = "http://axschema.org/namePerson/last"

def request_authentication(services, url, assoc_handle, return_to,
                           claimed=None, op_local=None, realm=None,
                           sreg = (('nickname', 'email'), ()),
                           ax = ((AX.email, AX.first, AX.last), ())):
    '''Request authentication (OpenID section 9).
    services is the list of discovered service types,
    url the OP service URL, assoc_handle the established session
    dictionary, and return_to the return URL.

    The return_to URL will also be passed as realm, and the
    OP may perform RP discovery on it; always request these
    data through SREG 1.0 as well.

    If AX or SREG 1.1 are supported, request email address,
    first/last name, or nickname.

    Return the URL that the browser should be redirected to.'''

    if is_op_endpoint(services):
        # claimed is an OP identifier
        claimed = op_local = None

    if claimed is None:
        claimed = "http://specs.openid.net/auth/2.0/identifier_select"
    if op_local is None:
        op_local = claimed
    if realm is None:
        realm = return_to
    data = {
        'openid.ns':"http://specs.openid.net/auth/2.0",
        'openid.mode':"checkid_setup",
        'openid.assoc_handle':assoc_handle,
        'openid.return_to':return_to,
        'openid.claimed_id':claimed,
        'openid.identity':op_local,
        'openid.realm':realm,
        'openid.sreg.required':'nickname,email',
        }
    sreg_req, sreg_opt = sreg
    sreg11 = {}
    if sreg_req or sreg_opt:
        data['openid.ns.sreg'] = "http://openid.net/sreg/1.0"
        if sreg_req:
            data['openid.sreg.required'] = sreg11['openid.sreg11.required'] = ','.join(sreg_req)
        if sreg_opt:
            data['openid.sreg.optional'] =  sreg11['openid.sreg11.optional'] =','.join(sreg_opt)
    if is_compat_1x(services):
        # OpenID 1.1 does not communicate claimed_ids. Put them into the return URL
        return_to += '&' if '?' in return_to else '?'
        return_to += '&openid1=' + urllib.quote(claimed)
        data['openid.return_to'] = return_to
        del data['openid.ns']
        del data['openid.claimed_id']
        del data['openid.realm']
        trust_root = urlparse.urlparse(return_to)[:3] + (None,None,None)
        data['openid.trust_root'] = urlparse.urlunparse(trust_root)
    ax_req, ax_opt = ax
    if "http://openid.net/srv/ax/1.0" in services and (ax_req or ax_opt):
        data.update({
            'openid.ns.ax':"http://openid.net/srv/ax/1.0",
            'openid.ax.mode':'fetch_request',
            })
        for uri in ax_req + ax_opt:
            data['openid.ax.type.'+AX.lookup(uri)] = uri
        if ax_req:
            data['openid.ax.required'] = ','.join(AX.lookup(uri) for uri in ax_req)
        if ax_opt:
            data['openid.ax.if_available'] = ','.join(AX.lookup(uri) for uri in ax_req)
    if "http://openid.net/extensions/sreg/1.1" in services and sreg11:
        data.update({
            'openid.ns.sreg11':"http://openid.net/extensions/sreg/1.1",
            })
        data.update(sreg11)
    if '?' in url:
        return url+'&'+urllib.urlencode(data)
    else:
        return url+"?"+urllib.urlencode(data)

# 11.4.2 Verifying Directly with the OpenID Provider
def verify_signature_directly(op_endpoint, response):
    '''Request that the OP verify the signature via Direct Verification'''

    request = [('openid.mode', 'check_authentication')]
    # Exact copies of all fields from the authentication response, except for
    # "openid.mode"
    request.extend((k, v) for k, (v,) in response.items() if 'openid.mode' != k)
    res = urllib.urlopen(op_endpoint, urllib.urlencode(request))
    if 200 != res.getcode():
        raise NotAuthenticated(NotAuthenticated.CONNECTION_REFUSED, res.getcode())
    response = parse_response(res.read())
    if 'true' != response['is_valid']:
        raise NotAuthenticated(NotAuthenticated.DIRECT_VERIFICATION_FAILED)

def _prepare_response(response):
    if isinstance(response, str):
        return cgi.parse_qs(response, keep_blank_values=True)
    # backwards compatibility: allow caller to pass parse_qs result
    # already
    pass
    return response

def authenticate(session, response):
    '''Process an authentication response.  session must be the
    established session (minimally including assoc_handle and
    mac_key), response the query string as given in the original URL
    (i.e. as the CGI variable QUERY_STRING).  If authentication
    succeeds, return the list of signed fields.  If the user was not
    authenticated, NotAuthenticated is raised.  If the HTTP request is
    invalid (missing parameters, failure to validate signature),
    different exceptions will be raised, typically ValueError.

    Callers must check openid.response_nonce for replay attacks.
    '''

    response = _prepare_response(response)

    # 1.1 compat: openid.ns may not be sent
    # if response['openid.ns'][0] != 'http://specs.openid.net/auth/2.0':
    #    raise ValueError('missing openid.ns')
    if session['assoc_handle'] != response['openid.assoc_handle'][0]:
        raise ValueError('incorrect session')
    if response['openid.mode'][0] == 'cancel':
        raise NotAuthenticated(NotAuthenticated.CANCELLED)
    if response['openid.mode'][0] != 'id_res':
        raise ValueError('invalid openid.mode')
    if  'openid.identity' not in response:
        raise ValueError('missing openid.identity')

    # Will not check nonce value - caller must verify this is not a replay

    signed = response['openid.signed'][0].split(',')
    query = []
    for name in signed:
        value = response['openid.'+name][0]
        value = '%s:%s\n' % (name, value)
        if sys.version_info >= (3,):
            value = value.encode('utf-8')
        query.append(value)
    query = b('').join(query)

    mac_key = base64.decodestring(session['mac_key'])
    transmitted_sig = base64.decodestring(b(response['openid.sig'][0]))
    computed_sig = hmac.new(mac_key, query, hashlib.sha1).digest()

    if transmitted_sig != computed_sig:
        raise ValueError('Invalid signature')

    # Check that all critical fields are signed. OpenID 2.0 says
    # that in a positive assertion, op_endpoint, return_to,
    # response_nonce and assoc_handle must be signed, and claimed_id
    # and identity if present in the response. 1.1 compatibility
    # says that response_nonce and op_endpoint may be missing.
    # In addition, OpenID 1.1 providers apparently fail to sign
    # assoc_handle often.
    if response['openid.mode'][0] == 'id_res':
        if 'return_to' not in signed or \
           ('openid.identity' in response and 'identity' not in signed) or \
           ('openid.claimed_id' in response and 'claimed_id' not in signed):
            raise ValueError, "Critical field missing in signature"

    return signed

# td.total_seconds only works in 2.7
def _total_seconds(td):
    return td.days*24*3600 + td.seconds

def verify(response, discovery_cache, find_association, nonce_seen):
    response = _prepare_response(response)
    if 'openid.ns' in response:
        ns = response['openid.ns'][0]
        if ns != 'http://specs.openid.net/auth/2.0':
            raise NotAuthenticated(NotAuthenticate.UNSUPPORTED_VERSION)
    else:
        ns = None
    mode = response['openid.mode'][0]
    if mode == 'cancel':
        raise NotAuthenticated(NotAuthenticated.CANCELLED)
    if mode != 'id_res':
        raise NotAuthenticated(NotAuthenticated.UNEXPECTED_MODE, mode)
    # Establish claimed ID
    if 'openid.claimed_id' in response:
        claimed_id = response['openid.claimed_id'][0]
        # 11.2. Drop Fragment from claimed_id
        fragment = claimed_id.find('#')
        if fragment != -1:
            claimed_id = claimed_id[:fragment]
    elif 'openid1' in response:
        claimed_id = response['openid1'][0]
    else:
        raise NotAuthenticated(NotAuthenticated.CLAIMED_ID_MISSING)
    discovered = discovery_cache(claimed_id)
    if not discovered:
        discovered = discover(claimed_id)
        if not discovered:
            raise NotAuthenticated(NotAuthenticated.DISCOVERY_FAILED, claimed_id)
    services, op_endpoint, op_local = discovered
    # For a provider-allocated claimed_id, there will be no op_local ID,
    # and there is no point checking it.
    if op_local and op_local != response['openid.identity'][0]:
        raise NotAuthenticated('Discovered and asserted local identifiers differ')
    # For OpenID 1.1, op_endpoint may not be included in the response
    if ('openid.op_endpoint' in response and
        op_endpoint != response['openid.op_endpoint'][0]):
        raise NotAuthenticated(NotAuthenticated.INCONSISTENT_IDS)
    # XXX verify protocol version, verify claimed_id wrt. original request,
    # verify return_to URL
    
    # verify the signature
    assoc_handle = response['openid.assoc_handle'][0]
    session = find_association(assoc_handle)
    if session:
        signed = authenticate(session, response)
    else:
        verify_signature_directly(op_endpoint, response)
        signed = response['openid.signed'][0].split(',')

    # Check the nonce. OpenID 1.1 doesn't have them
    if 'openid.response_nonce' in response:
        nonce = response['openid.response_nonce'][0]
        timestamp = parse_nonce(nonce)
        if _total_seconds(datetime.datetime.utcnow() - timestamp) > 10:
            # allow for at most 10s transmission time and time shift
            raise NotAuthenticated(NotAuthenticated.REPLAY_ATTACK)
        if nonce_seen(nonce):
            raise NotAuthenticated(NotAuthenticated.REPLAY_ATTACK)
    elif ns:
        raise NotAuthenticated(NotAuthenticated.MISSING_NONCE)
    return signed, claimed_id

def parse_nonce(nonce):
    '''Extract a datetime.datetime stamp from the nonce'''
    stamp = nonce.split('Z', 1)[0]
    stamp = time.strptime(stamp, "%Y-%m-%dT%H:%M:%S")[:6]
    stamp = datetime.datetime(*stamp)
    return stamp

def get_namespaces(resp):
    resp = _prepare_response(resp)
    res = {}
    for k, v in resp.items():
        if k.startswith('openid.ns.'):
            k = k.rsplit('.', 1)[1]
            res[v[0]] = k
    return res

def get_ax(resp, ns, validated):
    if "http://openid.net/srv/ax/1.0" not in ns:
        return {}
    ax = ns["http://openid.net/srv/ax/1.0"]+"."
    oax = "openid."+ax
    res = {}
    resp = _prepare_response(resp)
    for k, v in resp.items():
        if k.startswith(oax+"type."):
            k = k.rsplit('.',1)[1]
            value_name = oax+"value."+k
            if ax+"value."+k not in validated:
                continue
            res[v[0]] = resp[value_name][0]
    return res

def get_sreg(resp, validated):
    """Return the dictionary of simple registration parameters in resp,
    with the openid.sreg. prefix stripped."""
    res = {}
    resp = _prepare_response(resp)
    for k, v in resp.items():
        if k.startswith('openid.sreg.'):
            k = k[len('openid.sreg.'):]
            if 'sreg.'+k in validated:
                res[k] = v[0]
    return res

def get_email(resp):
    "Return the email address embedded response, or None."

    resp = _prepare_response(resp)
    validated = resp['openid.signed'][0]

    # SREG 1.0; doesn't require namespace, as the protocol doesn't
    # specify one
    if 'openid.sreg.email' in resp and \
       'sreg.email' in validated:
        return resp['openid.sreg.email'][0]

    ns = get_namespaces(resp)

    ax = get_ax(resp, ns, validated)
    if "http://axschema.org/contact/email" in ax:
        return ax["http://axschema.org/contact/email"]

    # TODO: SREG 1.1
    return None

def get_username(resp):
    """Return either nickname or (first, last) or None.
    This function is deprecated; use get_ax and get_sreg instead.
    """

    resp = _prepare_response(resp)
    validated = resp['openid.signed'][0]
    if 'openid.sreg.nickname' in resp and \
       'sreg.nickname' in validated:
        return resp['openid.sreg.nickname'][0]

    ns = get_namespaces(resp)

    ax = get_ax(resp, ns, validated)
    if "http://axschema.org/namePerson/first" in ax and \
       "http://axschema.org/namePerson/last" in ax:
        return (ax["http://axschema.org/namePerson/first"],
                ax["http://axschema.org/namePerson/last"])

    # TODO: SREG 1.1
    return
