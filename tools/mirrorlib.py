'''Library to support tools that access PyPI mirrors. The following
functional areas are covered:
- mirror selection (find_mirror)
- mirror verification
- key rollover
'''

################## Mirror Selection ##############################
import socket, time, datetime, errno, select

def _mirror_list(first):
    '''Generator producing all mirror names'''
    ord_a = ord('a')
    last = socket.gethostbyname_ex('last.pypi.python.org')
    cur_index = ord(first)-ord_a
    cur = first+'.pypi.python.org'
    while True:
        for family, _, _, _, sockaddr in socket.getaddrinfo(cur, 0, 0, socket.SOCK_STREAM):
            yield cur, family, sockaddr
        if last[0] == cur:
            break
        cur_index += 1
        if cur_index < 26:
            # a..z
            cur = chr(ord_a+cur_index)
        elif cur_index > 701:
            raise ValueError, 'too many mirrors'
        else:
            # aa, ab, ... zz
            cur = divmod(cur_index, 26)
            cur = chr(ord_a-1+cur[0])+chr(ord_a+cur[1])
        cur += '.pypi.python.org'

class _Mirror:
    # status values:
    # 0: wants to send
    # 1: wants to recv
    # 2: completed, ok
    # 3: completed, failed
    def __init__(self, name, family, ip):
        self.name = name
        self.family = family
        self.ip = ip
        self.socket = socket.socket(family, socket.SOCK_STREAM)
        self.socket.setblocking(0)
        self.started = time.time()
        try:
            self.socket.connect((name, 80))
        except socket.error, e:
            if e.errno != errno.EINPROGRESS:
                raise
        # now need to select for writing
        self.status = 0

    def write(self):
        url = 'last-modified'
        if self.name == 'a.pypi.python.org':
            # the master server doesn't provide last-modified,
            # as that would be pointless. Instead, /daytime can be
            # used as an indication of currency and responsiveness.
            url = 'daytime'
        self.socket.send('GET /%s HTTP/1.0\r\n'
                         'Host: %s\r\n'
                         '\r\n' % (url, self.name))
        self.status = 1
    
    def read(self):
        data = self.socket.recv(1200)
        self.response_time = time.time()-self.started
        # response should be much shorter
        assert len(data) < 1200
        self.socket.close()
        data = data.splitlines()
        if data[0].split()[1] == '200':
            # ok
            data = data[-1]
            try:
                self.last_modified = datetime.datetime.strptime(data, "%Y%m%dT%H:%M:%S")
                self.status = 2 # complete
            except ValueError:
                self.status = 3 # failed
        else:
            self.status = 3

    def failed(self):
        self.socket.close()
        self.status = failed()

    def results(self):
        return self.name, self.family, self.ip, self.response_time, self.last_modified

def _select(mirrors):
    # perform select call on mirrors dictionary
    rlist = []
    wlist = []
    xlist = []
    for m in mirrors.values():
        if m.status == 0:
            wlist.append(m.socket)
            xlist.append(m.socket)
        elif m.status == 1:
            rlist.append(m.socket)
            xlist.append(m.socket)
    rlist, wlist, xlist = select.select(rlist, wlist, xlist, 0)
    completed = []
    for s in wlist:
        mirrors[s].write()
    for s in rlist:
        m = mirrors[s]
        del mirrors[s]
        m.read()
        if m.status == 2:
            completed.append(m)
    for s in xlist:
        mirrors[s].failed()
        del mirrors[s]
    return completed

def _close(mirrors):
    for m in mirrors:
        m.close()

def _newest(mirrors):
    if not mirrors:
        raise ValueError, "no mirrors found"
    mirrors.sort(key=lambda m:m.last_modified)
    return mirrors[-1].results()

def find_mirror(start_with='a',
                good_response_time = 1,
                good_age = 30*60,
                slow_mirrors_wait = 5):
    '''find_mirror(start_with, good_response_time, good_age, slow_mirrors_wait) 
       -> name, family, IP, response_time, last_modified

    Find a PyPI mirror matching given criteria.
    start_with indicates the first mirror that should be considered (defaults to 'a').
    good_response_time is the maximum response time which lets this algorithm look no further;
    likewise, good_age is the maximum age acceptable to the caller.
    If this procedure goes on for longer than slow_mirrors_wait (default 5s), return even if
    not all mirrors have been responding.
    If no matching mirror can be found, the newest one that did response is returned.
    If no mirror can be found at all, ValueError is raised'''
    started = time.time()
    good_mirrors = []
    pending_mirrors = {} # socket:mirror
    good_last_modified = datetime.datetime.utcnow()-datetime.timedelta(seconds=good_age)
    for host, family, ip in _mirror_list(start_with):
        m = _Mirror(host, family, ip)
        pending_mirrors[m.socket] = m
        for m in _select(pending_mirrors):
            if m.response_time < good_response_time and m.last_modified > good_last_modified:
                _close(pending_mirrors)
                return m.results()
            else:
                good_mirrors.append(m)

    while pending_mirrors:
        if time.time() > started+slow_mirrors_wait and good_mirrors:
            # if we have looked for 5s for a mirror, and we already have one
            # return the newest one
            _close(pending)
            return _newest(good_mirrors)
        for m in _select(pending_mirrors):
            if m.response_time < good_response_time and m.last_modified > good_last_modified:
                _close(pending_mirrors)
                return m.results()
            else:
                good_mirrors.append(m)
    return _newest(good_mirrors)
