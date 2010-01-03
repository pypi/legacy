# system imports
import sys, os, urllib, cStringIO, traceback, cgi, binascii, getopt, md5
import time, random, smtplib, base64, sha, email, types, stat, urlparse
import re, zipfile, logging, pprint, sets, shutil, Cookie, subprocess
from zope.pagetemplate.pagetemplatefile import PageTemplateFile
from distutils.util import rfc822_escape

# Importing M2Crypto patches urllib; don't let them do that
orig = urllib.URLopener.open_https.im_func
from M2Crypto import EVP, DSA
urllib.URLopener.open_https = orig

import psycopg2

try:
    import cElementTree
except ImportError:
    from xml.etree import cElementTree

# local imports
import store, config, trove, versionpredicate, verify_filetype, rpc
import MailingLogger, openid
from mini_pkg_resources import safe_name

esc = cgi.escape
esq = lambda x: cgi.escape(x, True)

def enumerate(sequence):
    return [(i, sequence[i]) for i in range(len(sequence))]

safe_filenames = re.compile(r'.+?\.(exe|tar\.gz|bz2|rpm|deb|zip|tgz|egg|dmg|msi)$', re.I)
safe_username = re.compile(r'^[A-Za-z0-9._]+$')
safe_email = re.compile(r'^[a-zA-Z0-9._+@-]+$')
botre = re.compile(r'^$|brains|yeti|myie2|findlinks|ia_archiver|psycheclone|badass|crawler|slurp|spider|bot|scooter|infoseek|looksmart|jeeves', re.I)

class NotFound(Exception):
    pass
class Unauthorised(Exception):
    pass
class Forbidden(Exception):
    pass
class Redirect(Exception):
    pass
class RedirectTemporary(Exception): # 307
    pass
class FormError(Exception):
    pass

__version__ = '1.1'

# email sent to user indicating how they should complete their registration
rego_message = '''Subject: Complete your Cheese Shop registration
From: %(admin)s
To: %(email)s

To complete your registration of the user "%(name)s" with the python module
index, please visit the following URL:

  %(url)s?:action=user&otk=%(otk)s

'''

# password change request email
password_change_message = '''Subject: Cheese Shop password change request
From: %(admin)s
To: %(email)s

Someone, perhaps you, has requested that the password be changed for your
username, "%(name)s". If you wish to proceed with the change, please follow
the link below:

  %(url)s?:action=password_reset&email=%(email)s

You should then receive another email with the new password.

'''

# password reset email - indicates what the password is now
password_message = '''Subject: Cheese Shop password has been reset
From: %(admin)s
To: %(email)s

Your login is: %(name)s
Your password is now: %(password)s
'''

unauth_message = '''
<p>If you are a new user, <a href="%(url_path)s?:action=register_form">please
register</a>.</p>
<p>If you have forgotten your password, you can have it
<a href="%(url_path)s?:action=forgotten_password_form">reset for you</a>.</p>
'''

comment_message = '''Subject: New comment on %(package)s
From: PyPI operators <%(admin)s>
To: %(email)s
Reply-To: %(replyto)s

[REPLIES TO THIS MESSAGE WILL NOT GO TO THE COMMENTER]
%(author)s has made the following comment on your package.

%(comment)s

You can read all comments on %(url)s.
'''

chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'

providers = (('Google', 'http://www.google.com/favicon.ico', 'https://www.google.com/accounts/o8/id'),
             ('myOpenID', 'https://www.myopenid.com/favicon.ico', 'https://www.myopenid.com/'),
             ('Launchpad', 'https://launchpad.net/@@/launchpad.png', 'https://login.launchpad.net/')
             )

class Provider:
    def __init__(self, name, favicon, url):
        self.name = self.title = name
        self.favicon = favicon
        self.url = url

class _PyPiPageTemplate(PageTemplateFile):
    def pt_getContext(self, args=(), options={}, **kw):
        """Add our data into ZPT's defaults"""
        rval = PageTemplateFile.pt_getContext(self, args=args)
        options.update(rval)
        return options

cache_templates = True
if cache_templates:
    template_cache = {}
    def PyPiPageTemplate(file, dir):
        try:
            return template_cache[(file, dir)]
        except KeyError:
            t = _PyPiPageTemplate(file, dir)
            template_cache[(file, dir)] = t
            return t
else:
    PyPiPageTemplate = _PyPiPageTemplate

def comment_email(store, package, version, author, comment, add_recipients):
    emails = set()
    recipients = [r['user_name'] for r in store.get_package_roles(package)] + add_recipients
    for r in recipients:
        email = store.get_user(r)['email']
        if email:
            emails.add(email)
    info = {
        'package': package,
        'admin': store.config.adminemail,
        'replyto': store.config.replyto,
        'author': author,
        'email': ','.join(emails),
        'comment': comment,
        'url': '%s/%s/%s' % (store.config.url, package, version),
        }
    smtp = smtplib.SMTP(store.config.mailhost)
    smtp.sendmail(store.config.adminemail, list(emails), comment_message % info)


class FileUpload:
    pass

# poor man's markup heuristics so we don't have to use <PRE>,
# for when rst didn't work on the text...
br_patt = re.compile(" *\r?\n\r?(?= +)")
p_patt = re.compile(" *\r?\n(\r?\n)+")
def newline_to_br(text):
    text = re.sub(br_patt, "<BR/>", text)
    return re.sub(p_patt, "\n<P>\n", text)

def path2str(path):
    return " :: ".join(path)

def str2path(s):
    return [ node.strip() for node in s.split("::") ]


def transmute(field):
    if hasattr(field, 'filename') and field.filename:
        v = FileUpload()
        v.filename = field.filename
        v.value = field.value
        v.type = field.type
    else:
        v = field.value.decode('utf-8')
    return v

def decode_form(form):
    d = {}
    for k in form.keys():
        v = form[k]
        if isinstance(v, list):
            d[k] = [transmute(i) for i in v]
        else:
            d[k] = transmute(v)
    return d

class WebUI:
    ''' Handle a request as defined by the "env" parameter. "handler" gives
        access to the user via rfile and wfile, and a few convenience
        functions (see pypi).

        The handling of a request goes as follows:
        1. open the database
        2. see if the request is supplied with authentication information
        3. perform the action defined by :action ("home" if none is supplied)
        4a. handle exceptions sanely, including special ones like NotFound,
            Unauthorised, Redirect and FormError, or
        4b. commit changes to the database
        5. close the database to finish off

    '''
    def __init__(self, handler, env):
        self.handler = handler
        self.config = handler.config
        self.wfile = handler.wfile
        self.env = env
        random.seed(int(time.time())%256)
        self.nav_current = None
        self.privkey = None
        self.username = None
        self.authenticated = False # was a password or a valid cookie passed?
        self.loggedin = False      # was a valid cookie sent?
        self.usercookie = None

        # XMLRPC request or not?
        if self.env.get('CONTENT_TYPE') != 'text/xml':
            fs = cgi.FieldStorage(fp=handler.rfile, environ=env)
            self.form = decode_form(fs)
        else:
            self.form = None

        (protocol, machine, path, x, x, x) = urlparse.urlparse(self.config.url)
        self.url_machine = '%s://%s'%(protocol, machine)
        self.url_path = path

        # configure logging
        if self.config.logfile or self.config.mailhost:
            root = logging.getLogger()
            hdlrs = []
            if self.config.logfile:
                hdlr = logging.FileHandler(self.config.logfile)
                formatter = logging.Formatter(
                    '%(asctime)s %(name)s:%(levelname)s %(message)s')
                hdlr.setFormatter(formatter)
                hdlrs.append(hdlr)
            if self.config.logging_mailhost:
                hdlr = MailingLogger.MailingLogger(self.config.logging_mailhost,
                    self.config.fromaddr, self.config.toaddrs,
                    '[PyPI] %(line)s', False, flood_level=10)
                hdlrs.append(hdlr)
            root.handlers = hdlrs

    def run(self):
        ''' Run the request, handling all uncaught errors and finishing off
            cleanly.
        '''
        self.store = store.Store(self.config)
        try:
            try:
                self.inner_run()
            except NotFound:
                self.fail('Not Found', code=404)
            except Unauthorised, message:
                message = str(message)
                if not message:
                    message = 'You must login to access this feature'
                msg = unauth_message%self.__dict__
                self.fail(message, code=401, heading='Login required',
                    content=msg, headers={'WWW-Authenticate':
                    'Basic realm="pypi"'})
            except Forbidden, message:
                message = str(message)
                self.fail(message, code=403, heading='Forbidden')
            except Redirect, e:
                self.handler.send_response(301, 'Moved Permanently')
                self.handler.send_header('Location', e.args[0])
                self.handler.end_headers()
            except RedirectTemporary, e:
                # ask browser not to cache this redirect
                self.handler.send_response(307, 'Temporary Redirect')
                self.handler.send_header('Location', e.args[0])
                self.handler.end_headers()
            except FormError, message:
                message = str(message)
                self.fail(message, code=400, heading='Error processing form')
            except IOError, error:
                # ignore broken pipe errors (client vanished on us)
                if error.errno != 32: raise
            except psycopg2.OperationalError, message:
                # clean things up
                self.store.force_close()
                message = str(message)
                self.fail('Please try again later.\n<!-- %s -->'%message,
                    code=500, heading='Database connection failed')
            except:
                exc, value, tb = sys.exc_info()
                if ('connection limit exceeded for non-superusers'
                        not in str(value)):
                    logging.exception('Internal Error\n----\n%s\n----\n'%(
                        '\n'.join(['%s: %s'%x for x in self.env.items()])))
                if self.config.debug_mode == 'yes':
                    s = cStringIO.StringIO()
                    traceback.print_exc(None, s)
                    s = cgi.escape(s.getvalue())
                    self.fail('Internal Server Error', code=500,
                        heading='Error...', content='%s'%s)
                else:
                    s = '%s: %s'%(exc, value)
                    self.fail("There's been a problem with your request",
                        code=500, heading='Error...', content='%s'%s)
        finally:
            self.store.close()

    # these are inserted at the top of the standard template if set
    error_message = None
    ok_message = None

    def write_template(self, filename, **options):
        context = {}
        options.setdefault('norobots', False)
        options.setdefault('keywords', 'python programming language object'
            ' oriented web free source package index download software')
        options.setdefault('description', 'The Python Package Index is a'
            ' repository of software for the Python programming language.')
        options['providers'] = self.get_providers()
        context['data'] = options
        context['app'] = self
        fpi = self.config.url+self.env.get('PATH_INFO',"")
        try:
            options['FULL_PATH_INFO'] = fpi.decode("utf-8")
        except UnicodeError:
            raise NotFound, fpi + ' is not utf-8 encoded'

        template_dir = os.path.join(os.path.dirname(__file__), 'templates')
        context['standard_template'] = PyPiPageTemplate(
            "standard_template.pt", template_dir)

        template = PyPiPageTemplate(filename, template_dir)
        content = template(**context)

        self.handler.send_response(200, 'OK')
        if 'content-type' in options:
            self.handler.set_content_type(options['content-type'])
        else:
            self.handler.set_content_type('text/html; charset=utf-8')
        if self.usercookie:
            self.handler.send_header('Set-Cookie',
                                     'pypi='+self.usercookie+';path='+self.url_path)
        self.handler.end_headers()
        self.wfile.write(content.encode('utf-8'))

    def fail(self, message, title="Python Cheese Shop", code=400,
            heading=None, headers={}, content=''):
        ''' Indicate to the user that something has failed.
        '''
        self.handler.send_response(code, message)
        if '<' in content and '>' in content:
            html = True
            self.handler.set_content_type('text/html; charset=utf-8')
        else:
            html = False
            self.handler.set_content_type('text/plain; charset=utf-8')

        for k,v in headers.items():
            self.handler.send_header(k, v)
        self.handler.end_headers()

        if heading:
            if html:
                self.wfile.write('<strong>' + heading +
                    '</strong><br /><br />\n\n')
            else:
                self.wfile.write(heading + '\n\n')
        self.wfile.write(message)
        if html: self.wfile.write('<br /><br />\n')
        else: self.wfile.write('\n\n')
        self.wfile.write(content)

    def link_action(self, action_name=None, **vars):
        if action_name:
            vars[':action'] = action_name
        l = []
        for k,v in vars.items():
            l.append('%s=%s'%(urllib.quote(k.encode('utf-8')),
                urllib.quote(v.encode('utf-8'))))
        return self.url_path + '?' + '&'.join(l)

    navlinks = (
        ('browse', 'Browse packages'),
        ('submit_form', 'Package submission'),
        ('list_classifiers', 'List trove classifiers'),
        ('index', 'List packages'),
        ('rss', 'RSS (last 40 updates)'),
        ('role_form', 'Admin'),
    )
    def navlinks_html(self):
        links = []
        for action_name, desc in self.navlinks:
            desc = desc.replace(' ', '&nbsp;')
            if action_name == 'role_form' and (
                not self.username or not self.store.has_role('Admin', '')):
                continue

            cssclass = ''
            if action_name == self.nav_current:
                cssclass = 'selected'
            links.append('<li class="%s"><a class="%s" href="%s">%s</a></li>' %
                         (cssclass, cssclass, self.link_action(action_name), desc))
        return links


    def inner_run(self):
        ''' Figure out what the request is, and farm off to the appropriate
            handler.
        '''
        # See if this is the "simple" pages and signatures
        script_name = self.env.get('SCRIPT_NAME')
        if script_name and script_name == self.config.simple_script:
            return self.run_simple()
        if script_name and script_name == self.config.simple_sign_script:
            return self.run_simple_sign()
        if script_name == '/mirrors':
            return self.mirrors()
        # see if the user has provided a username/password
        auth = self.env.get('HTTP_CGI_AUTHORIZATION', '').strip()
        if auth:
            authtype, auth = auth.split()
            if authtype.lower() == 'basic':
                try:
                    un, pw = base64.decodestring(auth).split(':')
                except (binascii.Error, ValueError):
                    # Invalid base64, or not exactly one colon
                    un = pw = ''
                if self.store.has_user(un):
                    pw = sha.sha(pw).hexdigest()
                    user = self.store.get_user(un)
                    if pw != user['password']:
                        raise Unauthorised, 'Incorrect password'
                    self.username = un
                    self.authenticated = True
                    last_login = user['last_login']
                    # Only update last_login every minute
                    update_last_login = not last_login or (time.time()-time.mktime(last_login.timetuple()) > 60)
                    self.store.set_user(un, self.env['REMOTE_ADDR'], update_last_login)
        else:
            un = self.env.get('SSH_USER', '')
            if un and self.store.has_user(un):
                user = self.store.get_user(un)
                self.username = un
                self.authenticated = self.loggedin = True
                last_login = user['last_login']
                # Only update last_login every minute
                update_last_login = not last_login or (time.time()-time.mktime(last_login.timetuple()) > 60)
                self.store.set_user(un, self.env['REMOTE_ADDR'], update_last_login)

        # on logout, we set the cookie to "logged_out"
        self.cookie = Cookie.SimpleCookie(self.env.get('HTTP_COOKIE', ''))
        try:
            self.usercookie = self.cookie['pypi'].value
        except KeyError:
            self.usercookie = None

        name = self.store.find_user_by_cookie(self.usercookie)
        if name:
            self.loggedin = True
            self.authenticated = True # implied by loggedin
            self.username = name
            # no login time update, since looking for the
            # cookie did that already
            self.store.set_user(name, self.env['REMOTE_ADDR'], False)

        # Commit all user-related changes made up to here
        if self.username:
            self.store.commit()

        if self.env.get('CONTENT_TYPE') == 'text/xml':
            self.xmlrpc()
            return

        # now handle the request
        path = self.env.get('PATH_INFO', '')
        if self.form.has_key(':action'):
            action = self.form[':action']
        elif path:
            # Split into path items, drop leading slash
            try:
                items = path.decode('utf-8').split('/')[1:]
            except UnicodeError:
                raise NotFound(path + " is not UTF-8 encoded")
            if path == '/':
                self.form['name'] = ''
                action = 'index'
            elif len(items) >= 1:
                self.form['name'] = items[0]
                action = 'display'
            if len(items) >= 2 and items[1]:
                self.form['version'] = items[1]
                action = 'display'
            if len(items) == 3 and items[2]:
                action = self.form[':action'] = items[2]
        else:
            action = 'home'

        # make sure the user has permission
        if action in ('submit', ):
            if not self.authenticated:
                raise Unauthorised
            if self.store.get_otk(self.username):
                raise Unauthorised, "Incomplete registration; check your email"

        # handle the action
        if action in 'debug home browse rss index search submit doap display_pkginfo submit_pkg_info remove_pkg pkg_edit verify submit_form display register_form user_form forgotten_password_form user password_reset role role_form list_classifiers login logout files file_upload show_md5 doc_upload claim openid openid_return rate comment addcomment delcomment clear_auth addkey delkey'.split():
            getattr(self, action)()
        else:
            #raise NotFound, 'Unknown action'
            raise NotFound

        if action in 'submit submit_pkg_info pkg_edit remove_pkg'.split():
            self.rss_regen()

        # commit any database changes
        self.store.commit()

    def debug(self):
        self.fail('Debug info', code=200, content=str(self.env))

    def xmlrpc(self):
        rpc.handle_request(self)

    def simple_body(self, path):
        urls = self.store.get_package_urls(path)
        if urls is None:
            # check for normalized name
            names = self.store.find_package(path)
            if names and names[0] != path:
                raise Redirect, self.config.simple_script + '/' + names[0]
            raise NotFound, path + " does not have any releases"
        html = []
        html.append("""<html><head><title>Links for %s</title></head>"""
                    % path)
        html.append("<body><h1>Links for %s</h1>" % path)
        for href, rel, text in urls:
            if href.startswith('http://cheeseshop.python.org/pypi') or \
                    href.startswith('http://pypi.python.org/pypi') or \
                    href.startswith('http://www.python.org/pypi'):
                # Suppress URLs that point to us
                continue
            if rel:
                rel = ' rel="%s"' % rel
            else:
                rel = ''
            html.append("<a href='%s'%s>%s</a><br/>\n" % (href, rel, text))
        html.append("</body></html>")
        html = ''.join(html)
        return html

    def run_simple(self):
        path = self.env.get('PATH_INFO')
        if not path:
            raise Redirect, self.config.simple_script+'/'
        if path=='/':
            html = []
            html.append("<html><head><title>Simple Index</title></head>")
            html.append("<body>\n")
            for name,stable_version in self.store.get_packages():
                qname = urllib.quote(name.encode("utf-8"))
                html.append("<a href='%s/'>%s</a><br/>\n" % (qname,name))
            html.append("</body></html>")
            html = ''.join(html).encode('utf-8')
            self.handler.send_response(200, 'OK')
            self.handler.set_content_type('text/html; charset=utf-8')
            self.handler.end_headers()
            self.wfile.write(html)
            return

        path = path[1:]
        if path.endswith('/'):
            path = path[:-1]
        if '/' not in path:
            html = self.simple_body(path)
            self.handler.send_response(200, 'OK')
            self.handler.set_content_type('text/html; charset=utf-8')
            self.handler.end_headers()
            self.wfile.write(html)
            return
        raise NotFound, path

    def run_simple_sign(self):
        path = self.env.get('PATH_INFO')
        if not path:
            raise Redirect, self.config.simple_script+'/'
        path = path[1:]
        if '/' in path:
            raise NotFound, path
        html = self.simple_body(path)
        if not self.privkey:
            self.privkey = DSA.load_key(self.config.privkey)
        md = EVP.MessageDigest('sha1')
        md.update(html)
        digest = md.final()
        sig = self.privkey.sign_asn1(digest)
        self.handler.send_response(200, 'OK')
        self.handler.set_content_type('application/octet-stream')
        self.handler.end_headers()
        self.wfile.write(sig)

    def home(self, nav_current='home'):
        self.write_template('home.pt', title='PyPI')

    def rss(self):
        """Dump the last N days' updates as an RSS feed.
        """
        # determine whether the rss file is up to date
        if not os.path.exists(self.config.rss_file):
            self.rss_regen(self.config.rss_file)

        # TODO: throw in a last-modified header too?
        self.handler.send_response(200, 'OK')
        self.handler.set_content_type('text/xml; charset=utf-8')
        self.handler.end_headers()
        self.wfile.write(open(self.config.rss_file).read())

    def rss_regen(self, rss_file=None):
        if rss_file is None:
            rss_file = self.config.rss_file
        context = {}
        context['app'] = self

        template_dir = os.path.join(os.path.dirname(__file__), 'templates')
        template = PyPiPageTemplate('rss.xml', template_dir)
        content = template(**context)

        f = open(rss_file, 'w')
        try:
            f.write(content.encode('utf-8'))
        finally:
            f.close()

    def browse(self, nav_current='browse'):
        ua = self.env.get('HTTP_USER_AGENT', '')
        if botre.search(ua) is not None:
            self.handler.send_response(200, 'OK')
            self.handler.set_content_type('text/plain')
            self.handler.end_headers()
            self.wfile.write('This page intentionally blank.')
            return

        self.nav_current = nav_current
        content = cStringIO.StringIO()
        w = content.write

        trove = self.store.trove()
        qs = cgi.parse_qsl(self.env.get('QUERY_STRING', ''))

        # Analyze query parameters c= and show=
        cat_ids = []
        show_all = False
        for x in qs:
            if x[0] == 'c':
                try:
                    c = int(x[1])
                except:
                    continue
                if trove.trove.has_key(c):
                    cat_ids.append(c)
            elif x[0] == 'show' and x[1] == 'all':
                show_all = True
        cat_ids.sort()

        # XXX with 18 classifiers, postgres runs out of memory
        # So limit the number of simultaneous classifiers
        if len(cat_ids) > 8:
            self.fail("Too many classifiers", code=500)
            return

        # Fetch data from the database
        if cat_ids:
            packages_, tally = self.store.browse(cat_ids)
        else:
            # use cached version of top-level browse page
            packages_, tally = self.store.browse_tally()

        # we don't need the database any more, so release it
        self.store.close()

        # group tally into parent nodes
        boxes = {}
        for id, count in tally:
            if id in cat_ids:
                # Don't provide link to a selected category
                continue
            node = trove.trove[id]
            parent = ' :: '.join(node.path_split[:-1])
            boxes.setdefault(parent, []).append((node.name, id, count))
        # Sort per box alphabetically by name
        for box in boxes.values():
            box.sort()

        # order the categories; some are hardcoded to be first: topic,
        # environment, framework
        available_categories_ = []
        for cat in ("Topic", "Environment", "Framework"):
            if boxes.has_key(cat):
                available_categories_.append((cat, boxes.pop(cat)))
        # Sort the rest alphabetically
        boxes = boxes.items()
        boxes.sort()
        available_categories_.extend(boxes)

        # ... build packages viewdata
        packages_count = len(packages_)
        packages = []
        for p in packages_:
            packages.append(dict(name=p[0], version=p[1], summary=p[2],
                url=self.packageURL(p[0], p[1])))

        # ... build selected categories viewdata
        selected_categories = []
        for c in cat_ids:
            n = trove.trove[c]
            unselect_url = "%s?:action=browse" % self.url_path
            for c2 in cat_ids:
                if c==c2: continue
                unselect_url += "&c=%d" % c2
            selected_categories.append(dict(path_string=cgi.escape(n.path),
                    path = n.path_split,
                    pathstr = path2str(n.path_split),
                    unselect_url = unselect_url))

        # ... build available categories viewdata
        available_categories = []
        for name, subcategories in available_categories_:
            sub = []
            for subcategory, fid, count in subcategories:
                if fid in cat_ids:
                    add = cat_ids
                else:
                    add = cat_ids + [fid]
                add.sort()
                url = self.url_path + '?:action=browse'
                for c in add:
                    url += "&c=%d" % c
                sub.append(dict(
                    name = subcategory,
                    packages_count = count,
                    url = url,
                    description = subcategory[-1]))

            available_categories.append(dict(
                subcategories=sub, name=name, id=id))

        # only show packages if they're less than 20 and the user has
        # selected some categories, or if the user has explicitly asked
        # for them all to be shown by passing show=all on the URL
        show_packages = selected_categories and \
            (packages_count < 30 or show_all)

        # render template
        url = self.url_path + '?:action=browse&show=all'
        for c in cat_ids:
            url += '&c=%d' % c
        self.write_template('browse.pt', title="Browse",
            show_packages_url=url,
            show_packages=show_packages, packages=packages,
            packages_count=packages_count,
            selected_categories=selected_categories,
            available_categories=available_categories,
            norobots=True)

    def logout(self):
        self.loggedin = False
        self.store.delete_cookie(self.usercookie)
        self.home()

    def clear_auth(self):
        if self.username:
            raise Unauthorised, "Clearing basic auth"
        self.home()

    def login(self):
        if 'provider' in self.form:
            # OpenID login
            for p in providers:
                if p[0] == self.form['provider']:
                    break
            else:
                return self.fail('Unknown provider')
            stypes, url, assoc_handle = self.store.get_provider_session(p)
            return_to = self.config.url+'?:action=openid_return'
            url = openid.request_authentication(stypes, url, assoc_handle, return_to)
            self.store.commit()
            raise RedirectTemporary(url)
        if 'openid_identifier' in self.form:
            # OpenID with explicit ID
            kind, claimed_id = openid.normalize_uri(self.form['openid_identifier'])
            if kind == 'xri':
                return self.fail('xri resolution is not supported.')
            res = openid.discover(claimed_id)
            if not res:
                return self.fail('Discovery failed. If you think this is in error, please submit a bug report.')
            stypes, op_endpoint, op_local = res
            if not op_local:
                op_local = claimed_id
            assoc_handle = self.store.get_session_for_endpoint(claimed_id, stypes, op_endpoint)
            return_to = self.config.url+'?:action=openid_return'
            url = openid.request_authentication(stypes, op_endpoint, assoc_handle, return_to, claimed_id, op_local)
            self.store.commit()
            raise RedirectTemporary(url)
        if not self.authenticated:
            raise Unauthorised
        self.usercookie = self.store.create_cookie(self.username)
        self.loggedin = 1
        self.home()

    def role_form(self):
        ''' A form used to maintain user Roles
        '''
        self.nav_current = 'role_form'
        package_name = ''
        if self.form.has_key('package_name'):
            package_name = self.form['package_name']
            if not (self.store.has_role('Admin', package_name) or
                    self.store.has_role('Owner', package_name)):
                raise Unauthorised
            package = '''
<tr><th>Package Name:</th>
    <td><input type="text" readonly name="package_name" value="%s"></td>
</tr>
'''%cgi.escape(package_name)
        elif not self.store.has_role('Admin', ''):
            raise Unauthorised
        else:
            names = [x['name'] for x in self.store.get_packages()]
            names.sort()
            names = map(cgi.escape, names)
            s = '\n'.join(['<option value="%s">%s</option>'%(name, name)
                            for name in names])
            package = '''
<tr><th>Package Name:</th>
    <td><select name="package_name">%s</select></td>
</tr>
'''%s

        self.write_template('role_form.pt', title='Role maintenance',
            name=package_name, package=package)

    def package_role_list(self, name, heading='Assigned Roles'):
        ''' Generate an HTML fragment for a package Role display.
        '''
        l = ['<table class="roles">',
             '<tr><th class="header" colspan="2">%s</th></tr>'%heading,
             '<tr><th>User</th><th>Role</th></tr>']
        for assignment in self.store.get_package_roles(name):
            username = assignment[1]
            user = self.store.get_user(username)
            keyid = user['gpg_keyid']
            if keyid:
                username = "%s (PGP key %s)" % (username, keyid)
            l.append('<tr><td>%s</td><td>%s</td></tr>'%(
                cgi.escape(username),
                cgi.escape(assignment[0])))
        l.append('</table>')
        return '\n'.join(l)

    def role(self):
        ''' Add a Role to a user.
        '''
        # required fields
        if not self.form.has_key('package_name'):
            raise FormError, 'package_name is required'
        if not self.form.has_key('user_name'):
            raise FormError, 'user_name is required'
        if not self.form.has_key('role_name'):
            raise FormError, 'role_name is required'
        if not self.form.has_key(':operation'):
            raise FormError, ':operation is required'

        # get the values
        package_name = self.form['package_name']
        user_name = self.form['user_name']
        role_name = self.form['role_name']

        # further vali:dation
        if role_name not in ('Owner', 'Maintainer'):
            raise FormError, 'role_name not Owner or Maintainer'
        if not self.store.has_user(user_name):
            raise FormError, "user doesn't exist"

        # add or remove
        operation = self.form[':operation']
        if operation == 'Add Role':
            # make sure the user doesn't have the role
            if self.store.has_role(role_name, package_name, user_name):
                raise FormError, 'user has that role already'
            self.store.add_role(user_name, role_name, package_name)
            self.ok_message = 'Role Added OK'
        else:
            # make sure the user has the role
            if not self.store.has_role(role_name, package_name, user_name):
                raise FormError, "user doesn't have that role"
            if user_name == self.username:
                # Check that we are not removing the last maintainer
                for role in self.store.get_package_roles(package_name):
                    if role['role_name']=='Owner' and role['user_name'] != user_name:
                        break
                else:
                    # No other owner found
                    raise FormError, "You can't remove yourself as the last owner; remove the package instead"
            self.store.delete_role(user_name, role_name, package_name)
            self.ok_message = 'Role Removed OK'
            if user_name == self.username:
                # Might not have access to the package anymore
                return self.home()

        self.role_form()

    def _get_pkg_info(self, name, version):
        # get the appropriate package info from the database
        if name is None:
            try:
                name = self.form['name']
            except KeyError:
                raise NotFound, 'no package name supplied'
        if version is None:
            if self.form.has_key('version'):
                version = self.form['version']
            else:
                l = self.store.get_latest_release(name, hidden=False)
                try:
                    version = l[-1][1]
                except IndexError:
                    raise NotFound, 'no releases'
        return self.store.get_package(name, version), name, version

    def doap(self, name=None, version=None):
        '''Return DOAP rendering of a package.
        '''
        info, name, version = self._get_pkg_info(name, version)
        if not info:
            return self.fail('No such package / version',
                heading='%s %s'%(name, version),
                content="I can't find the package / version you're requesting")

        root = cElementTree.Element('rdf:RDF', {
            'xmlns:rdf': "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
            'xmlns:foaf': "http://xmlns.com/foaf/0.1/",
            'xmlns': "http://usefulinc.com/ns/doap#"})
        SE = cElementTree.SubElement

        project = SE(root, 'Project')

        def write_element(parent, attr, element):
            value = info[attr]
            if not value or value == 'UNKNOWN':
                return
            element = SE(parent, element)
            element.text = value
            element.tail = '\n'

         # Not handled here: version, keywords
        for attr, element in [('name', 'name'),
                              ('summary', 'shortdesc'),
                              ('description', 'description'),
                              ('download_url', 'download-page')
                              ]:
              write_element(project, attr, element)

        url = info['home_page']
        if url and url != 'UNKNOWN':
            url = SE(project, 'homepage', {'rdf:resource': url})
            url.tail = '\n'

        person = 'maintainer'
        if not info[person]:
            person = 'author'
        if info[person]:
            maint = SE(project, 'maintainer')
            pelem = SE(maint, 'foaf:Person')
            write_element(pelem, person, 'foaf:name')
            email = info[person+'_email']
            if email and email != 'UNKNOWN':
                obj = sha.new(email)
                email = binascii.b2a_hex(obj.digest())
                elem = SE(pelem, 'foaf:mbox_sha1sum')
                elem.text = email
            maint.tail = '\n'

        # Write version
        version = info['version']
        if version:
            release = SE(project, 'release')
            release.tail = '\n'
            velem = SE(release, 'Version')
            revision = SE(velem, 'revision')
            revision.text = version

        # write XML
        s = cStringIO.StringIO()
        s.write('<?xml version="1.0" encoding="UTF-8" ?>\n')
        cElementTree.ElementTree(root).write(s, 'utf-8')
        filename = '%s-%s.xml'%(name.encode('ascii', 'replace'),
            version.encode('ascii', 'replace'))

        self.handler.send_response(200, "OK")
        self.handler.set_content_type('text/xml; charset="UTF-8"')
        self.handler.send_header('Content-Disposition',
            'attachment; filename=%s'%filename)
        self.handler.end_headers()
        self.wfile.write(s.getvalue())

    def display_pkginfo(self, name=None, version=None):
        '''Reconstruct and send a PKG-INFO metadata file.
        '''

        info, name, version = self._get_pkg_info(name, version)
        if not info:
            return self.fail('No such package / version',
                heading='%s %s'%(name, version),
                content="I can't find the package / version you're requesting")

        content = cStringIO.StringIO()
        def w(s):
            if isinstance(s, unicode): s = s.encode('utf8')
            content.write(s)

        # We're up to PEP 314
        w("Metadata-Version: 1.1\n")

        # now the package info
        keys = info.keys()
        keys.sort()
        keypref = 'name version author author_email maintainer maintainer_email home_page download_url summary license description keywords platform'.split()
        for key in keypref:
            value = info[key]
            if not value:
                continue

            label = key.capitalize().replace('_', '-')

            if key == 'description':
                value = rfc822_escape(value)
            elif key.endswith('_email'):
                value = cgi.escape(value)
                value = value.replace('@', ' at ')
                value = value.replace('.', ' ')
            w('%s: %s\n'%(label, value))

        for col in ('requires', 'provides', 'obsoletes'):
            l = self.store.get_release_relationships(name, version, col)
            for entry in l:
                w('%s: %s\n' %(col.capitalize(), entry['specifier']))

        classifiers = self.store.get_release_classifiers(name, version)
        for c in classifiers:
            w('Classifier: %s\n' % (c['classifier'],))
        w('\n')

        # Not using self.success or page_head because we want
        # plain-text without all the html trappings.
        self.handler.send_response(200, "OK")
        self.handler.set_content_type('text/plain; charset=utf-8')
        self.handler.end_headers()
        s = content.getvalue()
        self.wfile.write(s)

    def release_nav(self):
        name = self.form.get('name')
        if not name:
            return ''

        # permission to do this?
        if not self.loggedin:
            return
        if not (self.store.has_role('Owner', name) or
                self.store.has_role('Admin', name) or
                self.store.has_role('Maintainer', name)):
            return ''

        # determine the version
        version = self.form.get('version')
        if not version:
            l = self.store.get_latest_release(name, hidden=False)
            try:
                version = l[-1][1]
            except IndexError:
                version = "(latest release)"

        un = urllib.quote_plus(name.encode('utf-8'))
        uv = urllib.quote_plus(version.encode('utf-8'))
        url = '%s?name=%s&amp;version=%s'%(self.url_path, un, uv)
        return '''<p class="release-nav">Package:
  <a href="%s?:action=role_form&amp;package_name=%s">admin</a> |
  <a href="%s&amp;:action=display">view</a> |
  <a href="%s&amp;:action=submit_form">edit</a> |
  <a href="%s&amp;:action=files">files</a> |
  <a href="%s&amp;:action=display_pkginfo">PKG-INFO</a>
</p>'''%(self.url_path, un, url, url, url, url)

    def quote_plus(self, data):
        return urllib.quote_plus(data)

    def display(self, name=None, version=None, ok_message=None,
            error_message=None):
        ''' Print up an entry
        '''
        # get the appropriate package info from the database
        if name is None:
            # check that we get one - and only one - name argument
            name = self.form.get('name', None)
            if name is None or isinstance(name, list):
                self.fail("Which package do you want to display?")

        using_latest=False
        if version is None:
            if self.form.has_key('version'):
                version = self.form['version']
            else:
                l = self.store.get_package_releases(name, hidden=False)
                if len(l) > 1:
                    return self.index(releases=l)
                l = self.store.get_latest_release(name, hidden=False)
                try:
                    version = l[-1][1]
                except IndexError:
                    using_latest=True
                    version = "(latest release)"

        if not using_latest:
             l = self.store.get_package_releases(name, hidden=False)
             latest_version = self.store.get_latest_release(name, hidden=False)
             try:
                 latest_version = l[0][1]
             except:
                 latest_version = 'Unknown'
                 # for now silently fail, this simply means we were not able
                 # to determine what the latest release is for one reason or
                 # another
        else:
             latest_version = None

        if latest_version==version:
            using_latest=True

        info = self.store.get_package(name, version)
        if not info:
            raise NotFound
#            return self.fail('No such package / version',
#                heading='%s %s'%(name, version),
#                content="I can't find the package / version you're requesting")

# RJ: disabled cheesecake because the (strange) errors were getting annoying
#        columns = 'name version author author_email maintainer maintainer_email home_page download_url summary license description description_html keywords platform cheesecake_installability_id cheesecake_documentation_id cheesecake_code_kwalitee_id'.split()
        columns = 'name version author author_email maintainer maintainer_email home_page download_url summary license description description_html keywords platform'.split()

        release = {'description_html': ''}
        for column in columns:
            value = info[column]
            if not info[column]: continue
            if isinstance(value, basestring) and value.strip() in (
                    'UNKNOWN', '<p>UNKNOWN</p>'): continue
            if column in ('name', 'version'): continue
            if column == 'description':
                # fallback if no description_html
                release['description_html'] = '<p>%s</p>'%newline_to_br(
                    cgi.escape(value))
            elif column.endswith('_email'):
                column = column[:column.find('_')]
                if release.has_key(column):
                    start = release[column]
                else:
                    start = ''
                value = value.replace('@', ' at ')
                value = value.replace('.', ' ')
                value = '%s <%s>'%(start, value)
            elif column.startswith('cheesecake_'):
                column = column[:-3]
                value = self.store.get_cheesecake_index(int(value))
            release[column] = value

        roles = {}
        for role, user in self.store.get_package_roles(name):
            roles.setdefault(role, []).append(user)

        def values(col):
            l = self.store.get_release_relationships(name, version, col)
            return [ cgi.escape(x['specifier']) for x in l]

        categories = []
        for c in self.store.get_release_classifiers(name, version):
            path = str2path(c['classifier'])
            url = "%s?:action=browse&c=%s" % (self.url_path, c['trove_id'])
            categories.append(dict(
                name = c['classifier'],
                path = path,
                pathstr = path2str(path),
                url = url,
                id = c['trove_id']))

        latest_version_url = self.config.url+'/'+name+'/'+latest_version

        # Compute rating data
        has_rated = self.loggedin and self.store.has_rating(name, version)
        latest_rating = self.loggedin and self.store.latest_rating(name)
        ratings, comments = self.store.get_ratings(name, version)
        total = 0.0
        hcomments = [] # as a hierarchy
        parent_comments = {}
        tally = [0]*6
        rating_by_id = {}
        for r in ratings:
            rating_by_id[r['id']] = r
            total += r['rating']
            tally[r['rating']] += 1

        for c in comments:
            add = c, []
            parent_comments[c['id']] = add[1]
            if c['in_reply_to']:
                parent_comments[c['in_reply_to']].append(add)
            else:
                hcomments.append(add)

        def render_comments(comments, toplevel):
            if not comments:
                return []
            result = ["<ul>\n"]
            for c,children in comments:
                message = cgi.escape(c['message'])
                message = '<br />'.join(message.split('\r\n'))
                date = c['date'].strftime("%Y-%m-%d")
                if not self.loggedin:
                    reply = ''
                elif self.username != c['user']:
                    reply = " <a href='%s?:action=comment&msg=%d'>Reply</a>" % (self.url_path, c['id'])
                elif toplevel:
                    reply = ''
                else:
                    if children:
                        msg = "Remove (including followups)"
                    else:
                        msg = "Remove"
                    reply = " <a href='%s?:action=delcomment&msg=%d&name=%s&version=%s'>%s</a>" % (self.url_path, c['id'], name, version, msg)
                if toplevel:
                    rating = rating_by_id[c['rating']]['rating']
                    if rating == 1:
                        rating = ', 1 point'
                    else:
                        rating = ', %s points' % rating
                else:
                    rating = ''
                result.append("<li>%s (%s%s):<br/>%s %s" % 
                                (c['user'], date, rating, message, reply))
                if children:
                    result.extend(render_comments(children, False))
                result.append("</li>\n")
            result.append("</ul>\n")
            return result
        comments = "".join(render_comments(hcomments, True))

        self.write_template('display.pt',
                            name=name, version=version, release=release,
                            description=release.get('summary') or name,
                            keywords=release.get('keywords', ''),
                            title=name + " " +version,
                            requires=values('requires'),
                            provides=values('provides'),
                            obsoletes=values('obsoletes'),
                            has_rated=has_rated,
                            latest_rating=latest_rating,
                            sum_ratings=total,
                            nr_ratings=len(ratings),
                            tally_ratings=tally,
                            comments=comments,
                            categories=categories,
                            roles=roles,
                            newline_to_br=newline_to_br,
                            usinglatest=using_latest,
                            latestversion=latest_version,
                            latestversionurl=latest_version_url,
                            action=self.link_action())

    def index(self, nav_current='index', releases=None):
        ''' Print up an index page
        '''
        self.nav_current = nav_current
        if releases is None:
            spec = self.form_metadata()
            if not spec.has_key('_pypi_hidden'):
                spec['_pypi_hidden'] = False
            i=0
            l = self.store.query_packages(spec)
            if len(l) == 1:
                self.form['name'] = l[0]['name']
                self.form['version'] = l[0]['version']
                return self.display()
        else:
            l = releases
        self.write_template('index.pt', title="Index of Packages",
            matches=l)

    STOPWORDS = sets.Set([
        "a", "and", "are", "as", "at", "be", "but", "by",
        "for", "if", "in", "into", "is", "it",
        "no", "not", "of", "on", "or", "such",
        "that", "the", "their", "then", "there", "these",
        "they", "this", "to", "was", "will", "with"
    ])
    def search(self, nav_current='index'):
        ''' Search for the indicated term.

        Try name first, then summary then description. Collate a
        score for each package that matches.
        '''
        term = self.form.get('term', '').strip().lower()
        term = re.sub(r'[^\w\s\.\-]', '', term)
        terms = [t for t in term.split() if t not in self.STOPWORDS]
        terms = filter(None, terms)
        if not terms:
            raise FormError, 'You need to supply a search term'

        d = {}
        columns = [
            ('name', 4),      # doubled for exact (case-insensitive) match
            ('summary', 2),
            ('keywords', 2),
            ('description', 1),
            ('author', 1),
            ('maintainer', 1),
        ]


        # score all package/release versions
        # require that each term occurs at least once (AND search)
        for t in terms:
            d_new = {}
            for col, score in columns:
                spec = {'_pypi_hidden': False, col: t}
                for r in self.store.query_packages(spec):
                    key = (r['name'], r['version'])
                    if d:
                        # must find current score in d
                        if key not in d:
                            # not a candidate anymore
                            continue
                        else:
                            e = d[key]
                    else:
                        # may find score in d_new
                        e = d_new.get(key, [0, r])
                    if col == 'name' and t == r['name'].lower():
                        e[0] += score*2
                    else:
                        e[0] += score
                    d_new[key] = e
            d = d_new
            if not d:
                # no packages match
                break

        # record the max value of _pypi_ordering per package
        max_ordering = {}
        for score,r in d.values():
            old_max = max_ordering.get(r['name'], -1)
            max_ordering[r['name']] = max(old_max, r['_pypi_ordering'])

        # drop old releases
        for (name, version), (score, r) in d.items():
            if max_ordering[name] != r['_pypi_ordering']:
                del d[(name, version)]

        # now sort by score and name ordering
        l = []
        scores = {}
        for k,v in d.items():
            l.append((-v[0], k[0].lower(), v[1]))
            scores[k[0]] = v[0]

        if len(l) == 1:
            self.form['name'] = l[0][-1]['name']
            self.form['version'] = l[0][-1]['version']
            return self.display()

        # sort and pull out just the record
        l.sort()
        l = [e[-1] for e in l]

        self.write_template('index.pt', matches=l, scores=scores,
            title="Index of Packages Matching '%s'"%term)

    def submit_form(self):
        ''' A form used to submit or edit package metadata.
        '''
        # submission of this form requires a login, so we should check
        # before someone fills it in ;)
        if not self.authenticated:
            raise Unauthorised, 'You must log in.'

        if not self.loggedin:
            # Authenticated, but not logged in - auto-login
            self.loggedin = True
            self.usercookie = self.store.create_cookie(self.username)

        # are we editing a specific entry?
        info = {}
        name = version = None
        if self.form.has_key('name') and self.form.has_key('version'):
            name = self.form['name']
            version = self.form['version']

            # permission to do this?
            if not (self.store.has_role('Owner', name) or
                    self.store.has_role('Admin', name) or
                    self.store.has_role('Maintainer', name)):
                raise Forbidden, 'Not Owner or Maintainer'

            # get the stored info
            for k,v in self.store.get_package(name, version).items():
                info[k] = v

        self.nav_current = 'submit_form'

        content= cStringIO.StringIO()
        w = content.write

        # display all the properties
        for property in 'name version author author_email maintainer maintainer_email home_page license summary description keywords platform download_url _pypi_hidden'.split():
            # get the existing entry
            if self.form.has_key(property):
                value = self.form[property]
            else:
                value = info.get(property, '')
            if value is None:
                value = ''

            # form field
            if property in ('name', 'version'):
                # not editable
                field = '<input id="%s" type="hidden" name="%s" value="%s">'%(
                    "property_%s" % property, property, urllib.quote(value.encode('utf-8')))
            if property == '_pypi_hidden':
                a = b = ''
                if value:
                    b = ' selected'
                else:
                    a = ' selected'
                field = '''<select name="_pypi_hidden">
                            <option value="0"%s>No</option>
                            <option value="1"%s>Yes</option>
                           </select>'''%(a,b)
            elif property in ('license', 'platform'):
                field = '''<textarea wrap="hard" name="%s" rows="5"
                    cols="80">%s</textarea><br />You should enter a full
                    description here only if appropriate classifiers aren\'t
                    available (see below).'''%(property, cgi.escape(value))
            elif property.endswith('description'):
                field = '''<textarea wrap="hard" name="%s" rows="5"
                    cols="80">%s</textarea><br />You may use
                    <a target="_new" href="http://docutils.sf.net/rst.html">ReStructuredText</a>
                    formatting for this field.'''%(property,
                    cgi.escape(value))
            else:
                field = '<input id="%s" size="60" name="%s" value="%s">'%(
                    "property_%s" % property, property, cgi.escape(value))

            # now spit out the form line
            label = property.replace('_', '&nbsp;').capitalize()
            if label in ('Name', 'Version'):
                req = 'class="required"'
            elif property == 'download_url':
                label = "Download URL"
            elif property == '_pypi_hidden':
                label = "Hidden"
            else:
                req = ''
            w('<tr><th %s>%s:</th><td>%s</td></tr>\n'%(req, label,
                field.encode('utf8')))

        # format relationships
        def relationship_input(relationship, value):
            w('''<tr><th>%s:</th>
   <td><textarea name="%s" cols="40" rows="5">%s</textarea></td>'''%(
    relationship.capitalize(), relationship,
    '\n'.join([v['specifier'] for v in value])))
        for col in ('requires', 'provides', 'obsoletes'):
            if name is not None:
                l = self.store.get_release_relationships(name, version, col)
            else:
                l = []
            relationship_input(col, l)

        # if we're editing
        if name is not None:
            release_cifiers = {}
            for classifier in self.store.get_release_classifiers(name, version):
                release_cifiers[classifier['classifier']] = 1
        else:
            release_cifiers = {}

        # now list 'em all
        w('''<tr><th>Classifiers:</th>
  <td><select multiple name="classifiers" size="10">
''')
        for classifier in self.store.get_classifiers():
            ctext = classifier['classifier']
            selected = release_cifiers.has_key(ctext) and ' selected' or ''
            htext = cgi.escape(ctext)
            w('<option%s value="%s">%s</option>'%(selected, htext, htext))

        w('''</select></td></tr>''')

        self.write_template('submit_form.pt',
            title='Submitting package information',
            fields=content.getvalue().decode('utf8'))

    def submit_pkg_info(self):
        ''' Handle the submission of distro metadata as a PKG-INFO file.
        '''
        # make sure the user is identified
        if not self.authenticated:
            raise Unauthorised, \
                "You must be identified to store package information"

        if not self.form.has_key('pkginfo'):
            raise FormError, \
                "You must supply the PKG-INFO file"

        # get the data
        pkginfo = self.form['pkginfo']
        if isinstance(pkginfo, FileUpload):
            pkginfo = pkginfo.value
        elif isinstance(pkginfo, str):
            try:
                pkginfo = pkginfo.decode('utf8')
            except UnicodeDecodeError:
                raise FormError, \
                    "Your PKG-INFO file must be either ASCII or UTF-8. " \
                    "If this is inconvenient, use 'python setup.py register'."
        mess = email.message_from_file(cStringIO.StringIO(pkginfo))
        data = {}
        for k, v in mess.items():
            # clean up the keys and values, normalise "-" to "_"
            k = k.lower().replace('-', '_')
            v = v.strip()

            # Platform, Classifiers, ...?
            if data.has_key(k):
                l = data[k]
                if isinstance(l, types.ListType):
                    l.append(v)
                else:
                    data[k] = [l, v]
            else:
                data[k] = v

        # flatten platforms into one string
        platform = data.get('platform', '')
        if isinstance(platform, types.ListType):
            data['platform'] = ','.join(data['platform'])

        # make sure relationships are lists
        for name in ('requires', 'provides', 'obsoletes'):
            if data.has_key(name) and not isinstance(data[name],
                    types.ListType):
                data[name] = [data[name]]

        # rename classifiers
        if data.has_key('classifier'):
            classifiers = data['classifier']
            if not isinstance(classifiers, types.ListType):
                classifiers = [classifiers]
            data['classifiers'] = classifiers

        # validate the data
        try:
            self.validate_metadata(data)
        except ValueError, message:
            raise FormError, message

        name = data['name']
        version = data['version']

        # don't hide by default
        if not data.has_key('_pypi_hidden'):
            data['_pypi_hidden'] = '0'

        # make sure the user has permission to do stuff
        has_package = self.store.has_package(name)
        if has_package and not (
                self.store.has_role('Owner', name) or
                self.store.has_role('Admin', name) or
                self.store.has_role('Maintainer', name)):
            raise Forbidden, \
                "You are not allowed to store '%s' package information"%name

        if not has_package:
            names = self.store.find_package(name)
            if names:
                raise Forbidden, "Package name conflicts with existing package '%s'" % names[0]

        # save off the data
        message = self.store.store_package(name, version, data)
        self.store.commit()

        # return a display of the package
        self.form['name'] = data['name']
        self.form['version'] = data['version']
        self.display(ok_message=message)

    def submit(self):
        ''' Handle the submission of distro metadata.
        '''
        # make sure the user is identified
        if not self.authenticated:
            raise Unauthorised, \
                "You must be identified to store package information"

        # pull the package information out of the form submission
        data = self.form_metadata()

        # validate the data
        try:
            self.validate_metadata(data)
        except ValueError, message:
            raise FormError, message

        name = data['name']
        version = data['version']

        # make sure the user has permission to do stuff
        has_package = self.store.has_package(name)
        if has_package and not (
                self.store.has_role('Owner', name) or
                self.store.has_role('Admin', name) or
                self.store.has_role('Maintainer', name)):
            raise Forbidden, \
                "You are not allowed to store '%s' package information"%name

        if not has_package:
            names = self.store.find_package(name)
            if names:
                raise Forbidden, "Package name conflicts with existing package '%s'" % names[0]

        # make sure the _pypi_hidden flag is set
        if not data.has_key('_pypi_hidden'):
            data['_pypi_hidden'] = False

        # save off the data
        message = self.store.store_package(name, version, data)
        self.store.commit()

        # return a display of the package
        self.display(ok_message=message)

    def form_metadata(self):
        ''' Extract metadata from the form.
        '''
        data = {}
        for k in self.form.keys():
            if k.startswith(':'): continue
            v = self.form[k]
            if k == '_pypi_hidden':
                v = v == '1'
            elif k in ('requires', 'provides', 'obsoletes'):
                if not isinstance(v, list):
                    v = [x.strip() for x in re.split('\s*[\r\n]\s*', v)]
                else:
                    v = [x.strip() for x in v]
                v = filter(None, v)
            elif isinstance(v, list):
                if k == 'classifiers':
                    v = [x.strip() for x in v]
                else:
                    v = ','.join([x.strip() for x in v])
            elif isinstance(v, FileUpload):
                continue
            else:
                v = v.strip()
            data[k.lower()] = v

        # make sure relationships are lists
        for name in ('requires', 'provides', 'obsoletes'):
            if data.has_key(name) and not isinstance(data[name],
                    types.ListType):
                data[name] = [data[name]]

        # make sure classifiers is a list
        if data.has_key('classifiers'):
            classifiers = data['classifiers']
            if not isinstance(classifiers, types.ListType):
                classifiers = [classifiers]
            data['classifiers'] = classifiers

        return data

    def verify(self):
        ''' Validate the input data.
        '''
        data = self.form_metadata()
        try:
            self.validate_metadata(data)
        except ValueError, message:
            self.fail(str(message), code=400, heading='Package verification')
            return

        self.write_template('message.pt', title='Package verification',
            message='Validated OK')

    def validate_metadata(self, data):
        ''' Validate the contents of the metadata.
        '''
        if not data.get('name', ''):
            raise ValueError, 'Missing required field "name"'
        if not data.get('version', ''):
            raise ValueError, 'Missing required field "version"'
        if data.has_key('metadata_version'):
            del data['metadata_version']

        # Traditionally, package names are restricted only for
        # technical reasons; / is not allowed because it may be
        # possible to break path names for file and documentation
        # uploads
        if '/' in data['name']:
            raise ValueError, "Invalid package name"

        # check requires and obsoletes
        def validate_version_predicates(col, sequence):
            try:
                map(versionpredicate.VersionPredicate, sequence)
            except ValueError, message:
                raise ValueError, 'Bad "%s" syntax: %s'%(col, message)
        for col in ('requires', 'obsoletes'):
            if data.has_key(col) and data[col]:
                validate_version_predicates(col, data[col])

        # check provides
        if data.has_key('provides') and data['provides']:
            try:
                map(versionpredicate.check_provision, data['provides'])
            except ValueError, message:
                raise ValueError, 'Bad "provides" syntax: %s'%message

        # check classifiers
        if data.has_key('classifiers'):
            d = {}
            for entry in self.store.get_classifiers():
                d[entry['classifier']] = 1
            for entry in data['classifiers']:
                if d.has_key(entry):
                    continue
                raise ValueError, 'Invalid classifier "%s"'%entry

    def pkg_edit(self):
        ''' Edit info about a bunch of packages at one go
        '''
        # make sure the user is identified
        if not self.authenticated:
            raise Unauthorised, \
                "You must be identified to edit package information"

        name = self.form['name']

        if self.form.has_key('submit_remove'):
            return self.remove_pkg()

        # make sure the user has permission to do stuff
        if not (self.store.has_role('Owner', name) or
                self.store.has_role('Admin', name) or
                self.store.has_role('Maintainer', name)):
            raise Forbidden, \
                "You are not allowed to edit '%s' package information"%name

        if self.form.has_key('submit_autohide'):
            value = self.form.has_key('autohide')
            self.store.set_package_autohide(name, value)

        if self.form.has_key('submit_comments'):
            value = self.form.has_key('comments')
            self.store.set_package_comments(name, value)

        # look up the current info about the releases
        releases = list(self.store.get_package_releases(name))
        reldict = {}
        for release in releases:
            info = {}
            for k,v in release.items():
                info[k] = v
            reldict[info['version']] = info

        # see if we're editing (note that form keys don't get unquoted)
        for key in self.form.keys():
            if key.startswith('hid_'):
                ver = urllib.unquote(key[4:])
                info = reldict[ver]
                info['_pypi_hidden'] = self.form[key] == '1'
            elif key.startswith('sum_'):
                ver = urllib.unquote(key[4:])
                info = reldict[ver]
                info['summary'] = self.form[key]

        # update the database
        for version, info in reldict.items():
            self.store.store_package(name, version, info)

        self.write_template('pkg_edit.pt', releases=releases, name=name,
                            autohide=self.store.get_package_autohide(name),
                            comments=self.store.get_package_comments(name),
            title="Package '%s' Editing"%name)

    def rate(self):
        '''Add or delete a rating.'''
        if not self.loggedin:
            raise Unauthorised, "You need to login to rate"

        name = self.form.get('name', '')
        version = self.form.get('version', '')

        if self.store.has_role('Owner', name) or self.store.has_role('Maintainer', name):
            raise Forbidden, "You cannot rate your own packages"

        if not name or not version:
            raise FormError, 'name and version required'

        if self.form.has_key('remove'):
            if not self.store.has_rating(name, version):
                raise Forbidden, "You did not rate that release"
            self.store.remove_rating(name, version)
            return self.display()

        if self.form.has_key('copy'):
            if self.store.has_rating(name, version):
                raise Forbidden, "You have already rated this release"
            if not self.form.has_key('fromversion'):
                raise FormError, "fromversion missing"
            comment = self.store.copy_rating(name, self.form['fromversion'], version)
            if comment:
                comment_email(self.store, name, version, self.username, comment, [])
            return self.display()
        if self.form.has_key('rate'):
            if self.store.has_rating(name, version):
                raise Forbidden, "You have already rated this release"
            if not self.form.has_key('rating'):
                raise FormError, "rating not provided"
            message = self.form['comment'].strip()
            if message and not self.store.get_package_comments(name):
                raise FormError, "package does not allow comments"
            self.store.add_rating(name, version, self.form['rating'], message)
            comment_email(self.store, name, version, self.username, message, [])
            return self.display()

        raise FormError, "Bad button"

    def comment(self):
        'Ask for a follow-up comment'
        if not self.form.has_key('msg'):
            raise FormError
        comment = self.store.get_comment(self.form['msg'])
        self.write_template('comment.pt', title='Reply to comment', 
                            comment=comment)

    def addcomment(self):
        'Post a follow-up comment'
        if not self.authenticated:
            raise Unauthorised, "You need to be identified to post a comment"
        if not self.form.has_key('msg') or not self.form.has_key('comment'):
            raise FormError
        msg = self.form['msg']
        comment = self.form['comment']
        orig = self.store.get_comment(msg)
        if not orig:
            raise FormError, "Invalid message"
        if orig['user'] == self.username:
            raise FormError, "You cannot respond to your own comments"
        comment = comment.strip()
        if not comment:
            raise FormError, "You must fill in a comment"

        name, version = self.store.add_comment(msg, comment)
        comment_email(self.store, name, version, self.username, comment, [orig['user']])

        return self.display(name=name, version=version)
        

    def delcomment(self):
        if not self.authenticated:
            raise Unauthorised, \
                "You must be identified to delete a comment"

        if not self.form.has_key('msg'):
            raise FormError

        msg = self.form['msg']
        comment = self.store.get_comment(msg)
        if not comment:
            raise FormError, "Invalid comment ID"
        if comment['user'] != self.username or not comment['in_reply_to']:
            raise FormError, "You cannot delete this comment" + comment['user']
        self.store.remove_comment(comment['id'])
        return self.display()

    def remove_pkg(self):
        ''' Remove a release or a whole package from the db.

            Only owner may remove an entire package - Maintainers may
            remove releases.
        '''
        # make sure the user is identified
        if not self.authenticated:
            raise Unauthorised, \
                "You must be identified to edit package information"

        # vars
        name = self.form['name']
        cn = cgi.escape(name)
        if self.form.has_key('version'):
            if isinstance(self.form['version'], type([])):
                version = [x for x in self.form['version']]
            else:
                version = [self.form['version']]
            cv = cgi.escape(', '.join(version))
            s = len(version)>1 and 's' or ''
            desc = 'release%s %s of package %s.'%(s, cv, cn)
        else:
            version = []
            desc = 'all information about package %s.'%cn

        # make sure the user has permission to do stuff
        if not (self.store.has_role('Owner', name) or
                self.store.has_role('Admin', name) or
                (version and self.store.has_role('Maintainer', name))):
            raise Forbidden, \
                "You are not allowed to edit '%s' package information"%name

        if self.form.has_key('submit_ok'):
            # ok, do it
            if version:
                for v in version:
                    self.store.remove_release(name, v)
                self.ok_message='Release removed'
            else:
                self.store.remove_package(name)
                self.ok_message='Package removed'
                return self.home()

        elif self.form.has_key('submit_cancel'):
            self.ok_message='Removal cancelled'

        else:
            message = '''You are about to remove %s<br />
                This action <em>cannot be undone</em>!<br />
                Are you <strong>sure</strong>?'''%desc

            fields = [
                {'name': ':action', 'value': 'remove_pkg'},
                {'name': 'name', 'value': name},
            ]
            for v in version:
                fields.append({'name': 'version', 'value': v})

            return self.write_template('dialog.pt', message=message,
                title='Confirm removal of %s'%desc, fields=fields)

        self.pkg_edit()

    # alias useful for the files ZPT page
    dist_file_types = store.dist_file_types
    dist_file_types_d = store.dist_file_types_d
    def files(self):
        '''List files and handle file submissions.
        '''
        name = version = None
        if self.form.has_key('name'):
            name = self.form['name']
        if self.form.has_key('version'):
            version = self.form['version']
        if not name or not version:
            self.fail(heading='Name and version are required',
                message='Name and version are required')
            return

        # if allowed, handle file upload
        maintainer = False
        if self.store.has_role('Maintainer', name) or \
                self.store.has_role('Admin', name) or \
                self.store.has_role('Owner', name):
            maintainer = True
            if self.form.has_key('submit_upload'):
                self.file_upload(response=False)

            elif (self.form.has_key('submit_remove') and
                    self.form.has_key('file-ids')):

                fids = self.form['file-ids']
                if isinstance(fids, list):
                    fids = [v for v in fids]
                else:
                    fids = [fids]

                for digest in fids:
                    try:
                        self.store.remove_file(digest)
                    except KeyError:
                        return self.fail('No such files to remove', code=200)

        self.write_template('files.pt', name=name, version=version,
            maintainer=maintainer, title="Files for %s %s"%(name, version))

    def pretty_size(self, size):
        n = 0
        while size > 1024:
            size /= 1024
            n += 1
        return '%d%sB'%(size, ['', 'K', 'M', 'G'][n])

    def show_md5(self):
        if not self.form.has_key('digest'):
            return NotFound
            #raise ValueError, 'invalid MD5 digest'
        digest = self.form['digest']
        try:
            self.store.get_file_info(digest)
        except KeyError:
            # invalid MD5 digest - it's not in the database
            raise NotFound
        self.handler.send_response(200, 'OK')
        self.handler.set_content_type('text/plain; charset=utf-8')
        self.handler.end_headers()
        self.wfile.write(digest)

    CURRENT_UPLOAD_PROTOCOL = "1"
    def file_upload(self, response=True):
        # make sure the user is identified
        if not self.authenticated:
            raise Unauthorised, \
                "You must be identified to edit package information"

        # Verify protocol version
        if self.form.has_key('protocol_version'):
            protocol_version = self.form['protocol_version']
        else:
            protocol_version = self.CURRENT_UPLOAD_PROTOCOL

        if protocol_version!=self.CURRENT_UPLOAD_PROTOCOL:
            # If a new protocol version is added, backward compatibility
            # with old distutils upload commands needs to be preserved
            raise NotImplementedError, "Unsupported file upload protocol"

        # figure the package name and version
        name = version = None
        if self.form.has_key('name'):
            name = self.form['name']
        if self.form.has_key('version'):
            version = self.form['version']
        if not name or not version:
            raise FormError, 'Name and version are required'

        # make sure the user has permission to do stuff
        if not (self.store.has_role('Owner', name) or
                self.store.has_role('Admin', name) or
                self.store.has_role('Maintainer', name)):
            raise Forbidden, \
                "You are not allowed to edit '%s' package information"%name

        # verify the release exists
        if not self.store.has_release(name, version):
            # auto-register the release...
            data = self.form_metadata()
            try:
                self.validate_metadata(data)
            except ValueError, message:
                raise FormError, message
            data['_pypi_hidden'] = False
            self.store.store_package(name, version, data)

        # verify we have enough information
        pyversion = 'source'
        content = filetype = md5_digest = comment = None
        if self.form.has_key('content'):
            content = self.form['content']
        if self.form.has_key('filetype'):
            filetype = self.form['filetype']
            if filetype == 'sdist':
                self.form['pyversion'] = 'source'
        if content is None or filetype is None:
            raise FormError, 'Both content and filetype are required'

        md5_digest = self.form['md5_digest']

        comment = self.form['comment']

        # python version?
        if self.form['pyversion']:
            pyversion = self.form['pyversion']
        elif filetype not in (None, 'sdist'):
            raise FormError, 'Python version is required for binary distribution uploads'

        # check for valid filenames
        if not hasattr(content, 'filename'):
            # I would say the only way this can happen is someone messing
            # with the form...
            raise FormError, 'invalid upload'
        filename = content.filename
        if not safe_filenames.match(filename):
            raise FormError, 'invalid distribution file'

        # check existing filename
        if self.store.has_file(name, version, filename):
            raise FormError, 'A file named "%s" already exists for ' \
                ' %s-%s. To fix problems with that file you' \
                ' should create a new release.'%(filename, name, version)

        # check for dodgy filenames
        if '/' in filename or '\\' in filename:
            raise FormError, 'invalid distribution file'

        # check whether file name matches package name
        prefix = safe_name(name.lower())
        if not safe_name(filename.lower()).startswith(prefix):
            raise FormError, 'The filename for %s must start with "%s" (any case)' % (name, prefix)

        # check for valid content-type
        mt = content.type or 'image/invalid'
        if mt.startswith('image/'):
            raise FormError, 'invalid distribution file'

        # grab content
        content = content.value

        if self.form.has_key('gpg_signature'):
            signature = self.form['gpg_signature']
            try:
                # If the signature is present, it may come
                # as an empty string, or as a file upload
                signature = signature.value
            except AttributeError:
                pass
        else:
            signature = None

        # nothing over 20M please
        if len(content) > 20*1024*1024:
            raise FormError, 'distribution file too large'
        if signature and len(signature) > 100*1024:
            raise FormError, 'invalid signature'

        # check the file for valid contents based on the type
        if not verify_filetype.is_distutils_file(content, filename, filetype):
            raise FormError, 'invalid distribution file'

        # Check whether signature is ASCII-armored
        if signature and not signature.startswith("-----BEGIN PGP SIGNATURE-----"):
            raise FormError, "signature is not ASCII-armored"

        # digest content
        m = md5.new()
        m.update(content)
        calc_digest = m.hexdigest()

        if not md5_digest:
            md5_digest = calc_digest
        elif md5_digest != calc_digest:
            self.fail(heading='MD5 digest mismatch',
                message='''The MD5 digest supplied does not match a
                digest calculated from the uploaded file (m =
                md5.new(); m.update(content); digest =
                m.hexdigest())''')
            return

        self.store.add_file(name, version, content, md5_digest,
            filetype, pyversion, comment, filename, signature)

        if response:
            self.handler.send_response(200, 'OK')
            self.handler.set_content_type('text/plain')
            self.handler.end_headers()
            self.wfile.write('OK\n')

    #
    # Documentation Upload
    #
    def doc_upload(self):
        # make sure the user is identified
        if not self.authenticated:
            raise Unauthorised, \
                "You must be identified to edit package information"

        # figure the package name and version
        name = version = None
        if self.form.has_key('name'):
            name = self.form['name']
        if not name:
            raise FormError, 'No package name given'

        # make sure the user has permission to do stuff
        if not (self.store.has_role('Owner', name) or
                self.store.has_role('Admin', name) or
                self.store.has_role('Maintainer', name)):
            raise Forbidden, \
                "You are not allowed to edit '%s' package information"%name

        if not self.form.has_key('content'):
            raise FormError, "No file uploaded"

        data = self.form['content'].value
        if len(data) > 10*1024*1024:
            raise FormError, "Documentation zip file is too large"
        data = cStringIO.StringIO(data)
        try:
            data = zipfile.ZipFile(data)
            members = data.namelist()
        except Exception,e:
            raise FormError, "Error uncompressing zipfile:" + str(e)

        # Assume the file is valid; remove any previous data
        path = os.path.join(self.config.database_docs_dir, name, "")
        if os.path.exists(path):
            shutil.rmtree(path)
        os.mkdir(path)
        try:
            for fname in members:
                fpath = os.path.normpath(os.path.join(path, fname))
                if not fpath.startswith(path):
                    raise ValueError, "invalid path name:"+fname
                if fname.endswith("/"):
                    os.mkdir(fpath)
                    continue
                upperdirs = os.path.dirname(fpath)
                if not os.path.exists(upperdirs):
                    os.makedirs(upperdirs)
                outfile = open(os.path.join(path, fname), "wb")
                outfile.write(data.read(fname))
                outfile.close()
        except Exception, e:
            raise FormError, "Error unpacking zipfile:" + str(e)

        self.store.log_docs(name, version)
        raise Redirect("http://packages.python.org/%s/" % name)

    #
    # classifiers listing
    #
    def list_classifiers(self):
        ''' Just return the list of classifiers.
        '''
        c = '\n'.join([c['classifier'] for c in self.store.get_classifiers()])
        self.handler.send_response(200, 'OK')
        self.handler.set_content_type('text/plain; charset=utf-8')
        self.handler.end_headers()
        self.wfile.write(c + '\n')

    #
    # User handling code (registration, password changing
    #
    def user_form(self):
        ''' Make the user authenticate before viewing the "register" form.
        '''
        if not self.authenticated:
            raise Unauthorised, 'You must authenticate'
        self.register_form()

    def register_form(self, openid_fields = (), username='', email='', openid=''):
        ''' Throw up a form for registering.
        '''
        info = {'name': '', 'password': '', 'confirm': '', 'email': '',
                'gpg_keyid': '', 'openids': [], 'openid_fields': openid_fields,
                'openid': openid}
        if self.username:
            user = self.store.get_user(self.username)
            info['new_user'] = False
            info['name'] = user['name']
            info['email'] = user['email']
            info['action'] = 'Update details'
            info['gpg_keyid'] = user['gpg_keyid'] or ""
            info['title'] = 'User profile'
            info['openids'] = self.store.get_openids(self.username)
            info['sshkeys'] = self.store.get_sshkeys(self.username)
            self.nav_current = 'user_form'
        else:
            info['new_user'] = True
            info['name'] = username
            info['email'] = email
            info['action'] = 'Register'
            info['title'] = 'Manual user registration'
            self.nav_current = 'register_form'

        self.write_template('register.pt', **info)

    def user(self):
        ''' Register, update or validate a user.

            This interface handles one of three cases:
                1. completion of rego with One Time Key
                2. new user sending in name, password and email
                3. updating existing user details for currently authed user
        '''
        message = ''

        info = {}
        for param in 'name password email otk confirm gpg_keyid'.split():
            v = self.form.get(param, '').strip()
            if v:
                info[param] = v
            else:
                if param == "gpg_keyid":
                    info[param] = ""

        # validate email and gpg key syntax
        if info.has_key('email'):
            if not safe_email.match(info['email']):
                raise FormError, 'Email is invalid (ASCII only)'
            if '@' not in info['email'] or '.' not in info['email']:
                raise FormError, 'Email is invalid'
        gpgid = info.get('gpg_keyid', '')
        gpgid = gpgid.strip()
        if gpgid:
            if not re.match("^[A-Fa-f0-9]{8,8}$", gpgid):
                raise FormError, 'GPG key ID is invalid'

        # email requirement check
        if 'email' not in info and 'otk' not in info:
            raise FormError, "Clearing the email address is not allowed"

        if info.has_key('otk'):
            # finish off rego
            if self.store.get_otk(info['otk']):
                response = 'Error: One Time Key invalid'
            else:
                # OK, delete the key
                self.store.delete_otk(info['otk'])
                response = 'Registration complete'

        elif self.username is None:
            for param in 'name email'.split():
                if not info.has_key(param):
                    raise FormError, '%s is required'%param

            if 'password' not in info or 'confirm' not in info:
                if 'openid.assoc_handle' not in self.form:
                    raise FormError, 'password and confirm are required'
                info['password'] = ''.join([random.choice(store.chars) for x in range(32)])
                # Recheck OpenID response
                qs = {}
                for key, value in self.form.items():
                    qs[key] = [value]
                session = self.store.get_session_by_handle(self.form['openid.assoc_handle'])
                if not session:
                    raise FormError, "Invalid session"
                provider, url, stypes, session = session
                try:
                    signed = openid.authenticate(session, qs)
                except Exception, e:
                    return self.fail('OpenID response has been tampered with:'+repr(e))
                if not openid.is_op_endpoint(stypes):
                    claimed_id = provider
                elif 'claimed_id' in signed:
                    claimed_id = qs['openid.claimed_id'][0]
                else:
                    return self.fail('Claimed ID got lost. Please report this as a bug.')
                if self.store.get_user_by_openid(claimed_id):
                    return self.fail('OpenID already associated with a different account')
                if 'response_nonce' in signed:
                    nonce = qs['openid.response_nonce'][0]
                else:
                    # OpenID 1.1
                    nonce = None
            else:
                claimed_id = nonce = None
                if not info.has_key('confirm') or info['password'] <> info['confirm']:
                    self.fail("password and confirm don't match", heading='Users')
                    return

            # validate a complete set of stuff
            # new user, create entry and email otk
            name = info['name']
            if not safe_username.match(name):
                raise FormError, 'Username is invalid (ASCII alphanum,.,_ only)'
            if self.store.has_user(name):
                self.fail('user "%s" already exists'%name,
                    heading='User registration')
                return
            if not self.form.has_key('agree'):
                self.fail('You need to confirm the usage agreement.',
                          heading='User registration')
                return
            olduser = self.store.get_user_by_email(info['email'])
            if olduser:
                raise FormError, 'You have already registered as user '+olduser['name']
            # we are about to commit the user; check the reply nonce
            if nonce and self.store.duplicate_nonce(nonce):
                return self.fail('replay attack detected')
            info['otk'] = self.store.store_user(name, info['password'],
                info['email'], info.get('gpg_keyid', ''))
            if claimed_id:
                self.store.associate_openid(name, claimed_id)
            info['url'] = self.config.url
            info['admin'] = self.config.adminemail
            self.send_email(info['email'], rego_message%info)
            response = 'Registration OK'
            message = 'You should receive a confirmation email shortly.'

        else:
            # update details
            user = self.store.get_user(self.username)
            password = info.get('password', '').strip()
            if not password:
                # no password entered - leave it alone
                password = None
            else:
                # make sure the confirm matches
                if password != info.get('confirm', ''):
                    self.fail("password and confirm don't match",
                        heading='User profile')
                    return
            email = info.get('email', user['email'])
            gpg_keyid = info.get('gpg_keyid', user['gpg_keyid'])
            self.store.store_user(self.username, password, email, gpg_keyid)
            response = 'Details updated OK'

        self.write_template('message.pt', title=response, message=message)

    def addkey(self):
        if not self.authenticated:
            raise Unauthorised

        if "key" not in self.form:
            raise FormError, "missing key"

        key = self.form['key'].splitlines()
        for line in key[1:]:
            if line.strip():
                raise FormError, "Invalid key format: multiple lines"
        key = key[0].strip()
        if not key.startswith('ssh-dss') and not key.startswith('ssh-rsa'):
            raise FormError, "Invalid key format: does not start with ssh-dss or ssh-rsa"
        self.store.add_sshkey(self.username, key)
        self.store.commit()
        self.update_sshkeys()
        return self.register_form()

    def delkey(self):
        if not self.authenticated:
            raise Unauthorised
        if "id" not in self.form:
            raise FormError, "missing parameter"
        try:
            id = int(self.form["id"])
        except:
            raise FormError, "invalid ID"
        for key in self.store.get_sshkeys(self.username):
            if key['id'] == id:
                break
        else:
            raise Unauthorised, "not your key"
        self.store.delete_sshkey(id)
        self.store.commit()
        self.update_sshkeys()
        return self.register_form()

    def forgotten_password_form(self):
        ''' Enable the user to reset their password.
        '''
        self.write_template("password_reset.pt", title="Request password reset")

    def password_reset(self):
        """Reset the user's password and send an email to the address given.
        """
        def resend_otk():
            info = {'otk':self.store.get_otk(user['name']), 'url':self.config.url,
                    'admin':self.config.adminemail, 'email': user['email'],
                    'name':user['name']}
            self.send_email(info['email'], rego_message%info)
            response = 'Registration OK'
            message = 'You should receive a confirmation email shortly.'
            self.write_template('message.pt', title="Resending registration key",
                message='Email with registration key resent')

        if self.form.has_key('email') and self.form['email'].strip():
            email = self.form['email'].strip()
            user = self.store.get_user_by_email(email)
            if not user:
                self.fail('email address unknown to me')
                return
            if self.store.get_otk(user['name']):
                return resend_otk()
            pw = ''.join([random.choice(chars) for x in range(10)])
            self.store.store_user(user['name'], pw, user['email'], None)
            info = {'name': user['name'], 'password': pw,
                'email':user['email']}
            info['admin'] = self.config.adminemail
            self.send_email(email, password_message%info)
            self.write_template('message.pt', title="Request password reset",
                message='Email sent with new password')
        elif self.form.has_key('name') and self.form['name'].strip():
            name = self.form['name'].strip()
            user = self.store.get_user(name)
            if not user:
                self.fail('user name unknown to me')
                return
            if self.store.get_otk(user['name']):
                return resend_otk()
            info = {'name': user['name'], 'url': self.config.url,
                 'email': urllib.quote(user['email'])}
            info['admin'] = self.config.adminemail
            self.send_email(user['email'], password_change_message%info)
            self.write_template('message.pt', title="Request password reset",
                message='Email sent to confirm password change')
        else:
            self.write_template("password_reset.pt", title="Request password reset",
                retry=True)

    def send_email(self, recipient, message):
        ''' Send an administrative email to the recipient
        '''
        smtp = smtplib.SMTP(self.config.mailhost)
        smtp.sendmail(self.config.adminemail, recipient, message)

    def packageURL(self, name, version):
        ''' return a URL for the link to display a particular package
        '''
        if not isinstance(name, str): name = name.encode('utf-8')
        if not isinstance(version, str): version = version.encode('utf-8')
        return u'%s/%s/%s'%(self.url_path, urllib.quote(name),
            urllib.quote(version))

    def packageLink(self, name, version):
        ''' return a link to display a particular package
        '''
        if not isinstance(name, unicode): name = name.decode('utf-8')
        if not isinstance(version, unicode): version = version.decode('utf-8')
        url = self.packageURL(name, version)
        name = cgi.escape(name)
        version = cgi.escape(version)
        return u'<a href="%s">%s&nbsp;%s</a>'%(url, name, version)

    def mirrors(self):
        ''' display the list of mirrors
        '''
        options = {'title': 'PyPI mirrors'}
        self.write_template('mirrors.pt', **options)

    def openid(self):
        self.write_template('openid.pt', title='OpenID Login')

    def claim(self):
        '''Claim an OpenID.'''
        if not self.loggedin:
            return self.fail('You are not logged in')
        if 'openid_identifier' in self.form:
            kind, claimed_id = openid.normalize_uri(self.form['openid_identifier'])
            if kind == 'xri':
                return self.fail('XRI resolution is not supported')
            res = openid.discover(claimed_id)
            if not res:
                return self.fail('Discovery failed. If you think this is in error, please submit a bug report.')
            stypes, op_endpoint, op_local = res
            if not op_local:
                op_local = claimed_id
            assoc_handle = self.store.get_session_for_endpoint(claimed_id, stypes, op_endpoint)
            return_to = self.config.url+'?:action=openid_return'
            url = openid.request_authentication(stypes, op_endpoint, assoc_handle, return_to, claimed_id, op_local)
            self.store.commit()
            raise RedirectTemporary(url)
        if not self.form.has_key("provider"):
            return self.fail('Missing parameter')
        for p in providers:
            if p[0] == self.form['provider']:
                break
        else:
            return self.fail('Unknown provider')
        stypes, url, assoc_handle = self.store.get_provider_session(p)
        return_to = self.config.url+'?:action=openid_return'
        url = openid.request_authentication(stypes, url, assoc_handle, return_to)
        self.store.commit()
        raise RedirectTemporary(url)

    def openid_return(self):
        '''Return from OpenID provider.'''
        qs = cgi.parse_qs(self.env['QUERY_STRING'])
        if 'openid.mode' not in qs:
            # Not an indirect call: treat it as RP discovery
            return self.rp_discovery()
        mode = qs['openid.mode'][0]
        if mode == 'cancel':
            return self.fail('Login cancelled')
        if mode == 'error':
            return self.fail('OpenID login failed: '+qs['openid.error'][0])
        if mode != 'id_res':
            return self.fail('OpenID login failed')
        session = self.store.get_session_by_handle(qs['openid.assoc_handle'][0])
        if not session:
            return self.fail('invalid session')
        provider, url, stypes, session = session
        try:
            signed = openid.authenticate(session, qs)
        except Exception, e:
            return self.fail('Login failed:'+repr(e))
        # the claimed ID in the response can't be trusted for signon requests,
        # as the user may have changed it when getting redirected.
        # For a signon login, the database has stored the claimed id in the
        # provider field of the session table.
        # XXX as the assoc_handle may not be signed, the return_to url should
        # contain a nonce for 1.1 providers
        if not openid.is_op_endpoint(stypes):
            claimed_id = provider
        elif 'claimed_id' in signed:
            claimed_id = qs['openid.claimed_id'][0]
        else:
            return self.fail('Claimed ID got lost. Please report this as a bug.')
        if 'response_nonce' in signed:
            nonce = qs['openid.response_nonce'][0]
        else:
            # OpenID 1.1
            nonce = None
            if 'openid.ns' in qs and qs['openid.ns'][0] == 'http://specs.openid.net/auth/2.0':
                return self.fail('OpenID 2.0 provider failed to protect against replay attacks')
        user = self.store.get_user_by_openid(claimed_id)
        # Three cases: logged-in user claimed some ID,
        # new login, or registration
        if self.loggedin:
            # claimed ID
            if user:
                return self.fail('OpenID is already claimed')
            if nonce and self.store.duplicate_nonce(nonce):
                return self.fail('replay attack detected')
            self.store.associate_openid(self.username, claimed_id)
            self.store.commit()
            return self.register_form()
        if user:
            # Login
            if nonce and self.store.duplicate_nonce(nonce):
                return self.fail('replay attack detected')
            self.store.commit()
            self.username = user['name']
            self.loggedin = self.authenticated = True
            self.usercookie = self.store.create_cookie(self.username)
            return self.home()
        # Fill openid response fields into register form as hidden fields
        del qs[':action']
        openid_fields = []
        for key, value in qs.items():
            openid_fields.append((key, value[0]))
        # propose email address based on response
        email = openid.get_email(qs)
        # propose user name based on response
        username = openid.get_username(qs)
        if isinstance(username, tuple):
            username = '.'.join(username)
        elif username is None:
            username = email.split('@')[0]
        username = username.replace(' ','.')
        username = re.sub('[^a-zA-Z0-9._]','',username)
        error = 'Please choose a username to complete registration'
        if self.store.has_user(username):
            suffix = 2
            while self.store.has_user("%s_%d" % (username, suffix)):
                suffix += 1
            username = "%s_%d" % (username, suffix)
        return self.register_form(openid_fields, username, email, claimed_id)

    def rp_discovery(self):
        payload = '''<xrds:XRDS  
                xmlns:xrds="xri://$xrds"  
                xmlns="xri://$xrd*($v*2.0)">  
                <XRD>  
                     <Service priority="1">  
                              <Type>http://specs.openid.net/auth/2.0/return_to</Type>  
                              <URI>%s</URI>  
                     </Service>  
                </XRD>  
                </xrds:XRDS>
        ''' % (self.config.url+'?:action=openid_return')
        self.handler.send_response(200)
        self.handler.send_header("Content-type", 'application/xrds+xml')
        self.handler.send_header("Content-length", str(len(payload)))
        self.handler.end_headers()
        self.handler.wfile.write(payload)

    def get_providers(self):
        res = []
        for r in providers:
            r = Provider(*r)
            r.login = "%s?:action=login&provider=%s" % (self.url_path, r.name)
            r.claim = "%s?:action=claim&provider=%s" % (self.url_path, r.name)
            res.append(r)
        return res

    def update_sshkeys(self):
        if not self.config.sshkeys_update:
            return
        p = subprocess.Popen([self.config.sshkeys_update],
                             stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)
        stdout = p.communicate()[0]
        if p.returncode != 0:
            raise FormError, "Key processing failed. Please contact the administrator. Detail: "+stdout
        
