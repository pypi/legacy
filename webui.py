# system imports
import sys, os, urllib, StringIO, traceback, cgi, binascii, getopt, md5
import time, random, smtplib, base64, sha, email, types, stat, urlparse
import re, zipfile, logging
from simpletal import simpleTAL, simpleTALES
from distutils.util import rfc822_escape
from xml.sax import saxutils


# local imports
import store, config, flamenco2, trove, versionpredicate

esc = cgi.escape
esq = lambda x: cgi.escape(x, True)

def enumerate(sequence):
    return [(i, sequence[i]) for i in range(len(sequence))]

safe_filenames = re.compile(r'.+?\.(exe|tar\.gz|bz2|rpm|deb|zip|tgz)$', re.I)
safe_zipnames = re.compile(r'(purelib|platlib|headers|scripts|data).+', re.I)

def xmlescape(s):
    ' make sure we escape a string '
    return saxutils.escape(str(s))


class NotFound(Exception):
    pass
class Unauthorised(Exception):
    pass
class Forbidden(Exception):
    pass
class Redirect(Exception):
    pass
class FormError(Exception):
    pass

__version__ = '1.1'

# email sent to user indicating how they should complete their registration
rego_message = '''Subject: Complete your PyPI registration
From: %(admin)s
To: %(email)s

To complete your registration of the user "%(name)s" with the python module
index, please visit the following URL:

  %(url)s?:action=user&otk=%(otk)s

'''

# password change request email
password_change_message = '''Subject: PyPI password change request
From: %(admin)s
To: %(email)s

Someone, perhaps you, has requested that the password be changed for your
username, "%(name)s". If you wish to proceed with the change, please follow
the link below:

  %(url)s?:action=password_reset&email=%(email)s

You should then receive another email with the new password.

'''

# password reset email - indicates what the password is now
password_message = '''Subject: PyPI password has been reset
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

chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'

class WebUI:
    ''' Handle a request as defined by the "env" parameter. "handler" gives
        access to the user via rfile and wfile, and a few convenience
        functions (see pypi).

        The handling of a request goes as follows:
        1. open the database
        2. see if the request is supplied with authentication information
        3. perform the action defined by :action ("index" if none is supplied)
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

        # XMLRPC request or not?
        if self.env.get('CONTENT_TYPE') != 'text/xml':
            self.form = cgi.FieldStorage(fp=handler.rfile, environ=env)
        else:
            self.form = None

        (protocol, machine, path, x, x, x) = urlparse.urlparse(self.config.url)
        self.url_machine = '%s://%s'%(protocol, machine)
        self.url_path = path

        # configure logging
        if self.config.logging:
            root = logging.getLogger()
            hdlr = logging.FileHandler(self.config.logging)
            formatter = logging.Formatter('%(asctime)s %(message)s')
            hdlr.setFormatter(formatter)
            root.handlers = [hdlr]
            simpleTALLogger = logging.getLogger("simpleTAL")
            simpleTALESLogger = logging.getLogger("simpleTALES")
            simpleTALLogger.setLevel(logging.INFO)
            simpleTALESLogger.setLevel(logging.INFO)


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
            except Redirect, path:
                self.handler.send_response(301)
                self.handler.send_header('Location', path)
            except FormError, message:
                message = str(message)
                self.fail(message, code=400, heading='Error processing form')
            except:
                s = StringIO.StringIO()
                traceback.print_exc(None, s)
                s = cgi.escape(s.getvalue())
                self.fail('Internal Server Error', code=500, heading='Error...',
                    content='%s'%s)
        finally:
            self.store.close()

    # these are inserted at the top of the standard template if set
    error_message = None
    ok_message = None

    def write_template(self, filename, **options):
        context = simpleTALES.Context(allowPythonPath=True)
        context.addGlobal('options', options)
        context.addGlobal('app', self)

        # standard template has macros innit
        fn = os.path.join(os.path.dirname(__file__), 'templates',
            'standard_template.pt')
        templateFile = open(fn, 'r')
        standard_template = simpleTAL.compileXMLTemplate(templateFile)
        context.addGlobal("standard_template", standard_template)

        filename = os.path.join(os.path.dirname(__file__), 'templates',
            filename)
        templateFile = open(filename, 'r')
        try:
            template = simpleTAL.compileXMLTemplate(templateFile)
        finally:
            templateFile.close()

        self.handler.send_response(200, 'OK')
        self.handler.send_header('Content-Type', 'text/html')
        self.handler.end_headers()
        template.expand(context, self.wfile)

    def fail(self, message, title="Python Packages Index", code=400,
            heading=None, headers={}, content=''):
        ''' Indicate to the user that something has failed.
        '''
        self.handler.send_response(code, message)
        self.handler.send_header('Content-Type', 'text/plain')
        for k,v in headers.items():
            self.handler.send_header(k, v)
        self.handler.end_headers()
        if heading:
            self.wfile.write(heading + '\n\n')
        self.wfile.write(message)
        self.wfile.write('\n\n')
        self.wfile.write(content)

    def random_banner(self):
        banner_num = random.randint(0, 64)
        colors = [
             '#3399ff',  '#6699cc',  '#3399ff',  '#0066cc',  '#3399ff',
             '#0066cc',  '#0066cc',  '#3399ff',  '#3399ff',  '#3399ff',
             '#3399ff',  '#6699cc',  '#3399ff',  '#3399ff',  '#ffffff',
             '#6699cc',  '#0066cc',  '#3399ff',  '#0066cc',  '#3399ff',
             '#6699cc',  '#0066cc',  '#6699cc',  '#3399ff',  '#3399ff',
             '#6699cc',  '#3399ff',  '#3399ff',  '#6699cc',  '#6699cc',
             '#0066cc',  '#6699cc',  '#0066cc',  '#6699cc',  '#0066cc',
             '#0066cc',  '#6699cc',  '#3399ff',  '#0066cc',  '#bbd6f1',
             '#0066cc',  '#6699cc',  '#3399ff',  '#3399ff',  '#0066cc',
             '#0066cc',  '#0066cc',  '#6699cc',  '#6699cc',  '#3399ff',
             '#3399ff',  '#6699cc',  '#0066cc',  '#0066cc',  '#6699cc',
             '#0066cc',  '#6699cc',  '#3399ff',  '#6699cc',  '#3399ff',
             '#d6ebff',  '#6699cc',  '#3399ff',  '#0066cc',
             ]
        return {
            'bgcolor': colors[banner_num],
            'src': 'http://www.python.org/pics/PyBanner%03d.gif'%banner_num,
            }

    def link_action(self, action_name=None, **vars):
        if action_name:
            vars[':action'] = action_name
        return self.url_path + '?' + urllib.urlencode(vars)

    navlinks = (
        ('home', 'PyPI home'),
        ('browse', 'Browse packages'),
        ('search_form', 'Search'),
        ('index', 'List all packages'),
        ('submit_form', 'Package submission'),
        ('list_classifiers', 'List trove classifiers'),
        ('rss', 'RSS (last 20 updates)'),
        ('role_form', 'Admin'),
    )
    def navlinks_html(self):
        links = []
        for action_name, desc in self.navlinks:
            desc = desc.replace(' ', '&nbsp;')
            if action_name == 'role_form' and (
                not self.username or not self.store.has_role('Admin', '')):
                continue
            if action_name == self.nav_current:
                links.append('<strong>%s</strong>' % desc)
            else:
                links.append('<a href="%s">%s</a>' % (self.link_action(action_name), desc))
        return links


    def inner_run(self):
        ''' Figure out what the request is, and farm off to the appropriate
            handler.
        '''
        # see if the user has provided a username/password
        self.username = None
        auth = self.env.get('HTTP_CGI_AUTHORIZATION', '').strip()
        if auth:
            authtype, auth = auth.split()
            if authtype.lower() == 'basic':
                un, pw = base64.decodestring(auth).split(':')
                if self.store.has_user(un):
                    pw = sha.sha(pw).hexdigest()
                    user = self.store.get_user(un)
                    if pw != user['password']:
                        raise Unauthorised, 'Incorrect password'
                    self.username = un
                    self.store.set_user(un, self.env['REMOTE_ADDR'])

        if self.env.get('CONTENT_TYPE') == 'text/xml':
            self.xmlrpc()
            return

        # now handle the request
        if self.form.has_key(':action'):
            action = self.form[':action'].value
        else:
            action = 'home'

        # make sure the user has permission
        if action in ('submit', ):
            if self.username is None:
                raise Unauthorised
            if self.store.get_otk(self.username):
                raise Unauthorised

        # handle the action
        if action in 'home browse rss submit display_pkginfo submit_pkg_info remove_pkg pkg_edit verify submit_form display search_form register_form user_form forgotten_password_form user password_reset index search role role_form list_classifiers login logout files file_upload'.split():
            getattr(self, action)()
        else:
            raise ValueError, 'Unknown action'

        if action in 'submit submit_pkg_info pkg_edit remove_pkg'.split():
            self.rss_regen()

        # commit any database changes
        self.store.commit()

    def xmlrpc(self):
        import rpc
        rpc.handle_request(self)

    def home(self, nav_current='home'):
        self.write_template('home.pt', title='Home')

    def rss(self):
        """Dump the last N days' updates as an RSS feed.
        """
        # determine whether the rss file is up to date
        rss_file = os.path.join(os.path.split(self.config.database)[0],
            'rss.xml')
        if not os.path.exists(rss_file):
            self.rss_regen(rss_file)
#        else:
#            rss_mtime = os.stat(rss_file)[stat.ST_MTIME]
#            if rss_mtime < self.store.last_modified():
#                self.rss_regen(rss_file)

        # TODO: throw in a last-modified header too?
        self.handler.send_response(200, 'OK')
        self.handler.send_header('Content-Type', 'text/xml')
        self.handler.end_headers()
        self.wfile.write(open(rss_file).read())

    def rss_regen(self, rss_file=None):
        if rss_file is None:
            rss_file = self.config.rss_file
        f = open(rss_file, 'w')
        f.write('''<?xml version="1.0"?>
<!-- name="generator" content="PyPI/%s" -->
<!DOCTYPE rss PUBLIC "-//Netscape Communications//DTD RSS 0.91//EN" "http://my.netscape.com/publish/formats/rss-0.91.dtd">
<rss version="0.91">
 <channel>
  <title>PyPI recent updates</title>
  <link>%s%s</link>
  <description>Updates to the Python Packages Index (PyPI)</description>
  <language>en</language>
'''%(__version__, self.url_machine, self.url_path))
        for name, version, date, summary in self.store.latest_releases():
            date = str(date)
            f.write('''  <item>
    <title>%s %s</title>
    <link>http://www.python.org%s</link>
    <description>%s</description>
    <pubDate>%sZ</pubDate>
   </item>
'''%(xmlescape(name), xmlescape(version), xmlescape(self.packageURL(name,
    version)), xmlescape(summary), date))
        f.write('''
  </channel>
</rss>
''')
        f.close()

    def browse(self, nav_current='browse'):
        content = StringIO.StringIO()
        w = content.write

        cursor = self.store.get_cursor()
        tree = trove.Trove(cursor)
        qs = os.environ.get('QUERY_STRING', '')
        l = [x for x in cgi.parse_qsl(qs) if not x[0].startswith(':')]
        q = flamenco2.Query(cursor, tree, l)
        # we don't need the database any more, so release it
        self.store.close()

        # do the query
        matches, choices = q.list_choices()
        matches.sort()

        # format the result
        if q.query:
            query_info = ['Current query:<br>\n']
            for fld, value in q.query:
                n = q.trove[int(value)]
                query_info.append(cgi.escape(n.path))
                query_info.append(
                    ' <a href="%s?:action=browse&%s">[ignore]</a><br>\n'%(
                        self.url_path, q.as_href(ignore=value)))
        else:
            query_info = ['<p>Currently querying everything']
        query_info = ''.join(query_info) + '</p>'

        choices.sort()
        for header, headid, options in choices:
            if not options:
                continue
            options.sort()
            option_data = []
            for field, count in options:
                full = header + ' :: ' + field[-1]
                fid = tree[tree.getid(field)].id
                option_data.append({
                        'count': len(count),
                        'full': full,
                        'href': '%s?:action=browse&%s' % (self.url_path,
                                                          q.as_href(add=fid)),
                        'description': field[-1]})
            choice_data.append({
                    'option_data': option_data,
                    'header': header,
                    'headid': headid})
        self.write_template('browse.pt', choice_data=choice_data,
                            query=q, title="Browse", matches=matches,
                            query_info=query_info)

    def index(self, nav_current='index'):
        ''' Print up an index page
        '''
        self.nav_current = nav_current
        content = StringIO.StringIO()
        w = content.write
        spec = self.form_metadata()
        if not spec.has_key('_pypi_hidden'):
            spec['_pypi_hidden'] = False
        i=0
        l = self.store.query_packages(spec)
        self.write_template('index.pt', title="Index of Packages", matches=l)

    def search(self):
        """Same as index, but don't disable the search or index nav links
        """
        self.index(nav_current=None)

    def logout(self):
        raise Unauthorised
    def login(self):
        if not self.username:
            raise Unauthorised
        self.home()

    def search_form(self):
        ''' A form used to generate filtered index displays
        '''
        self.write_template('search_form.pt', title="Search",
                            action=self.link_action())

    def role_form(self):
        ''' A form used to maintain user Roles
        '''
        self.nav_current = 'role_form'
        package_name = ''
        if self.form.has_key('package_name'):
            package_name = self.form['package_name'].value
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
        s = '\n'.join(['<option value="%s">%s (%s)</option>'%(x['name'],
            x['name'], x['email']) for x in self.store.get_users()])
        users = '<select name="user_name">%s</select>'%s
        if self.store.has_role('Admin', None):
            admin = '<option value="Admin">Admin</option>'
        else:
            admin = ''

        # now write the body
        s = '''
<p>Use this form to add or remove a user\'s Role for a Package. The
available Roles are defined as:
<dl><dt><b>Owner</b></dt><dd>
  Owns a package name, may assign Maintainer Role for that name.  The
  first user to register information about a package is deemed Owner
  of the package name.  The Admin user may change this if necessary.
  May submit updates for the package name.
  </dd>
<dt><b>Maintainer</b></dt><dd>
  Can submit and update info for a particular package name.
  </dd></dl>
        </p>
<p>&nbsp;</p>

<form method="POST">
<input type="hidden" name=":action" value="role">
<table class="form">
<tr><th>User Name:</th>
    <td>%s</td>
</tr>
%s
<tr><th>Role to Add:</th>
    <td><select name="role_name">
        <option value="Owner">Owner</option>
        <option value="Maintainer">Maintainer</option>
        %s
        </select></td>
</tr>
<tr><td>&nbsp;</td>
    <td><input type="submit" name=":operation" value="Add Role">
        <input type="submit" name=":operation" value="Remove Role"></td></tr>
</table>
</form>
'''%(users, package, admin)

        # list the existing role assignments
        if package_name:
            s += self.package_role_list(package_name, 'Existing Roles')
        self.success(heading='Role maintenance', content=s)

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
        package_name = self.form['package_name'].value
        user_name = self.form['user_name'].value
        role_name = self.form['role_name'].value

        # further validation
        if role_name not in ('Owner', 'Maintainer'):
            raise FormError, 'role_name not Owner or Maintainer'
        if not self.store.has_user(user_name):
            raise FormError, "user doesn't exist"

        # add or remove
        operation = self.form[':operation'].value
        if operation == 'Add Role':
            # make sure the user doesn't have the role
            if self.store.has_role(role_name, package_name, user_name):
                raise FormError, 'user has that role already'
            self.store.add_role(user_name, role_name, package_name)
            message = 'Role Added OK'
        else:
            # make sure the user has the role
            if not self.store.has_role(role_name, package_name, user_name):
                raise FormError, "user doesn't have that role"
            self.store.delete_role(user_name, role_name, package_name)
            message = 'Role Removed OK'

        # XXX make this call display
        self.success(message=message, heading='Role maintenance')

    def display_pkginfo(self, name=None, version=None):
        '''Reconstruct and send a PKG-INFO metadata file.
        '''
        # get the appropriate package info from the database
        if name is None:
            name = self.form['name'].value
        if version is None:
            if self.form.has_key('version'):
                version = self.form['version'].value
            else:
                raise NotImplementedError, 'get the latest version'
        info = self.store.get_package(name, version)
        if not info:
            return self.fail('No such package / version',
                heading='%s %s'%(name, version),
                content="I can't find the package / version you're requesting")

        content = StringIO.StringIO()
        w = content.write

        # Some things (download-url, classifier) aren't in metadata v1.0 as
        # defined in PEP 241, but they'd be nice to publish anyway.  PEP 241
        # doesn't take an explicit stance on the handling of undefined fields.
        w("Metadata-Version: 1.0\n")

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

            w('%s: %s\n' % (label, value))

        for col in ('requires', 'provides', 'obsoletes'):
            l = self.store.get_release_relationships(name, version, col)
            for entry in l:
                w('%s: %s\n' %(col.capitalize(), entry))

        classifiers = self.store.get_release_classifiers(name, version)
        for c in classifiers:
            w('Classifier: %s\n' % (c,))
        w('\n')

        # Not using self.success or page_head because we want
        # plain-text without all the html trappings.
        self.handler.send_response(200, "OK")
        self.handler.send_header('Content-Type', 'text/plain')
        self.handler.end_headers()
        self.wfile.write(content.getvalue())

    def quote_plus(self, data):
        return urllib.quote_plus(data)

    def display(self, name=None, version=None, ok_message=None,
            error_message=None):
        ''' Print up an entry
        '''
        # get the appropriate package info from the database
        if name is None:
            name = self.form.getfirst('name')
            if name is None:
                self.fail("Which package do you want to display?")
        if version is None:
            if self.form.has_key('version'):
                version = self.form.getfirst('version')
            else:
                l = self.store.get_package_releases(name, hidden=False)
                try:
                    version = l[-1][1]
                except IndexError:
                    version = "(latest release)"

        info = self.store.get_package(name, version)
        rows0 = 'name version author author_email maintainer maintainer_email home_page download_url summary license description keywords platform'.split()
        row_names = {}
        rows = []
        values = {}
        for r in rows0:
            value = info[r]
            if not info[r]: continue
            rows.append(r)
            if r == 'download_url':
                row_names[r] = "Download URL"
            else:
                row_names[r] = r.capitalize().replace('_', ' ')
            if (r in ('download_url', 'url', 'home_page')
                    and value != 'UNKNOWN'):
                values[r] = '<a href="%s">%s</a>' % (value, cgi.escape(value))
            elif r == 'description':
                values[r] = '<pre">%s</pre>' % cgi.escape(value)
            elif r.endswith('_email'):
                value = cgi.escape(value)
                value = value.replace('@', ' at ')
                value = value.replace('.', ' ')
                values[r] = cgi.escape(value)
            else:
                values[r] = cgi.escape(value)

        content=StringIO.StringIO()
        w=content.write
        def format_list(title, l):
            w('<tr><th>%s: </th><td>'%title.capitalize())
            w('\n<br>'.join([cgi.escape(x) for x in l]))
            w('\n</td></tr>\n')

        for col in ('requires', 'provides', 'obsoletes'):
            l = self.store.get_release_relationships(name, version, col)
            if l: format_list(col, l)
        dependencies = content.getvalue()

        content=StringIO.StringIO()
        w=content.write

        # package's role assignments
        w(self.package_role_list(name))

        # package's journal
        w('<table class="history">\n')
        w('<tr><th colspan=4 class="header">Journal</th></tr>\n')
        w('<tr><th>Date</th><th>User</th><th>Action</th></tr>\n')
        for entry in self.store.get_journal(name, version):
            w('<tr><td nowrap>%s</td><td>%s</td><td>%s</td></tr>\n'%(
                entry[1], entry[2], entry[0]))
        w('\n</table>\n')

        roles_and_journal = content.getvalue()

        self.write_template('display.pt', 
                            name=name,
                            version=version,
                            values=values,
                            rows=rows,
                            row_names=row_names,
                            dependencies=dependencies,
                            roles_and_journal=roles_and_journal,
                            title=name + " " +version,
                            action=self.link_action())
        return

    def submit_form(self):
        ''' A form used to submit or edit package metadata.
        '''
        # submission of this form requires a login, so we should check
        # before someone fills it in ;)
        if not self.username:
            raise Unauthorised, 'You must log in.'

        # are we editing a specific entry?
        info = {}
        name = version = None
        if self.form.has_key('name') and self.form.has_key('version'):
            name = self.form['name'].value
            version = self.form['version'].value

            # permission to do this?
            if not (self.store.has_role('Owner', name) or
                    self.store.has_role('Maintainer', name)):
                raise Forbidden, 'Not Owner or Maintainer'

            # get the stored info
            for k,v in self.store.get_package(name, version).items():
                info[k] = v

        content = StringIO.StringIO()
        w = content.write
        self.nav_current = 'submit_form'
        w('''
<p>To submit information to this index, you have three options:</p>
<p id="submitheader">1. Use the new distutils "<a href="http://www.python.org/dev/doc/devel/dist/package-index.html">register</a>" command. If you\'re not using python 2.3, you need to:</p>
<ol>
<li>Copy <a href="http://mechanicalcat.net/tech/pypi/register.py">register.py</a> to your
python lib "distutils/command" directory (typically something like
"/usr/lib/python2.2/distutils/command/").
<li>Run "setup.py register" as you would normally run "setup.py" for your
distribution - this will register your distribution\'s metadata with the
index.
<li>... that\'s <em>it</em>
</ol>

<p id="submitheader">2. Or upload your PKG-INFO file (generated by distutils) here:</p>
<form method="POST" enctype="multipart/form-data">
<input type="hidden" name=":action" value="submit_pkg_info">
<table class="form">
<tr><th>PKG-INFO file:</th>
    <td><input size="40" type="file" name="pkginfo"></td>
</tr>
<tr><td>&nbsp;</td><td><input type="submit" value="Add Package Info"></td></tr>
</table>
</form>

<p id="submitheader">3. Or enter the information manually:</p>
<form method="POST">
<input type="hidden" name=":action" value="submit">
<table class="form">
''')

        # display all the properties
        for property in 'name version author author_email maintainer maintainer_email home_page license summary description keywords platform download_url _pypi_hidden'.split():
            # get the existing entry
            if self.form.has_key(property):
                value = self.form[property].value
            else:
                value = info.get(property, '')
            if value is None:
                value = ''

            # form field
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
            elif property.endswith('description'):
                field = '<textarea wrap="hard" name="%s" rows="5" ' \
                    'cols="80">%s</textarea>'%(property, cgi.escape(value))
            else:
                field = '<input size="60" name="%s" value="%s">'%(property,
                    cgi.escape(value))

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
            w('<tr><th %s>%s:</th><td>%s</td></tr>\n'%(req, label, field))

        # format relationships
        def relationship_input(relationship, value):
            w('''<tr><th>%s:</th>
   <td><textarea name="%s" cols="40" rows="5">%s</textarea></td>'''%(
    relationship.capitalize(), relationship, '\n'.join(value)))
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
                release_cifiers[classifier] = 1
        else:
            release_cifiers = {}

        # now list 'em all
        w('''<tr><th>Classifiers:</th>
  <td><select multiple name="classifiers" size="10">
''')
        for classifier in self.store.get_classifiers():
            selected = release_cifiers.has_key(classifier) and ' selected' or ''
            w('<option%s value="%s">%s</option>'%(selected,
                cgi.escape(classifier), classifier))

        w('''
</select></td></tr>
<tr><th class="required">highlighted</th><td>information is required</td></tr>
<tr><td>&nbsp;</td><td><input type="submit" value="Add Information"></td></tr>
</table>
</form>
''')

        self.success(heading='Submitting package information',
            content=content.getvalue())

    def submit_pkg_info(self):
        ''' Handle the submission of distro metadata as a PKG-INFO file.
        '''
        # make sure the user is identified
        if not self.username:
            raise Unauthorised, \
                "You must be identified to store package information"

        if not self.form.has_key('pkginfo'):
            raise FormError, \
                "You must supply the PKG-INFO file"

        # get the data
        mess = email.message_from_file(self.form['pkginfo'].file)
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
        if self.store.has_package(name) and not (
                self.store.has_role('Owner', name) or
                self.store.has_role('Maintainer', name)):
            raise Forbidden, \
                "You are not allowed to store '%s' package information"%name

        # save off the data
        message = self.store.store_package(name, version, data)
        self.store.commit()

        # return a display of the package
        self.form.value.append(cgi.MiniFieldStorage('name', data['name']))
        self.form.value.append(cgi.MiniFieldStorage('version', data['version']))
        self.display(ok_message=message)

    def submit(self):
        ''' Handle the submission of distro metadata.
        '''
        # make sure the user is identified
        if not self.username:
            raise Unauthorised, \
                "You must be identified to store package information"

        # pull the package information out of the form submission
        data = self.form_metadata()

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

        # validate the data
        try:
            self.validate_metadata(data)
        except ValueError, message:
            raise FormError, message

        name = data['name']
        version = data['version']

        # make sure the user has permission to do stuff
        if self.store.has_package(name) and not (
                self.store.has_role('Owner', name) or
                self.store.has_role('Maintainer', name)):
            raise Forbidden, \
                "You are not allowed to store '%s' package information"%name

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
                    v = re.split('\s*[\r\n]\s*', v.value)
                else:
                    v = [x.value.strip() for x in v]
            elif isinstance(v, list):
                if k == 'classifiers':
                    v = [x.value.strip() for x in v]
                else:
                    v = ','.join([x.value.strip() for x in v])
            else:
                v = v.value.strip()
            data[k.lower()] = v
        return data

    def verify(self):
        ''' Validate the input data.
        '''
        data = self.form_metadata()
        try:
            self.validate_metadata(data)
        except ValueError, message:
            self.fail(message, code=400, heading='Package verification')
            return

        self.success(heading='Package verification', message='Validated OK')

    def validate_metadata(self, data):
        ''' Validate the contents of the metadata.
        '''
        if not data.has_key('name'):
            raise ValueError, 'Missing required field "name"'
        if not data.has_key('version'):
            raise ValueError, 'Missing required field "version"'
        if data.has_key('metadata_version'):
            del data['metadata_version']

        # check requires and obsoletes
        def validate_version_predicates(col, sequence):
            try:
                map(versionpredicate.VersionPredicate, sequence)
            except ValueError, message:
                raise ValueError, 'Bad "%s" syntax: %s'%(col, message)
        for col in ('requires', 'obsoletes'):
            if data.has_key(col):
                validate_version_predicates(col, data[col])

        # check provides
        if data.has_key('provides'):
            try:
                map(versionpredicate.check_provision, data['provides'])
            except ValueError, message:
                raise ValueError, 'Bad "provides" syntax: %s'%(col, message)

        # check classifiers
        if data.has_key('classifiers'):
            d = {}
            for entry in self.store.get_classifiers():
                d[entry] = 1
            for entry in data['classifiers']:
                if d.has_key(entry):
                    continue
                raise ValueError, 'Invalid classifier "%s"'%entry

    def pkg_edit(self):
        ''' Edit info about a bunch of packages at one go
        '''
        # make sure the user is identified
        if not self.username:
            raise Unauthorised, \
                "You must be identified to edit package information"

        name = self.form['name'].value

        if self.form.has_key('submit_remove'):
            return self.remove_pkg()

        # make sure the user has permission to do stuff
        if not (self.store.has_role('Owner', name) or
                self.store.has_role('Maintainer', name)):
            raise Forbidden, \
                "You are not allowed to edit '%s' package information"%name

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
                info['_pypi_hidden'] = self.form[key].value == '1'
            elif key.startswith('sum_'):
                ver = urllib.unquote(key[4:])
                info = reldict[ver]
                info['summary'] = self.form[key].value

        # update the database
        for version, info in reldict.items():
            self.store.store_package(name, version, info)

        self.write_template('pkg_edit.pt', releases=releases, name=name,
            title="Package '%s' Editing"%name)

    def remove_pkg(self):
        ''' Remove a release or a whole package from the db.

            Only owner may remove an entire package - Maintainers may
            remove releases.
        '''
        # make sure the user is identified
        if not self.username:
            raise Unauthorised, \
                "You must be identified to edit package information"

        # vars
        name = self.form['name'].value
        cn = cgi.escape(name)
        if self.form.has_key('version'):
            if isinstance(self.form['version'], type([])):
                version = [x.value for x in self.form['version']]
            else:
                version = [self.form['version'].value]
            cv = cgi.escape(', '.join(version))
            s = len(version)>1 and 's' or ''
            desc = 'release%s %s of package %s.'%(s, cv, cn)
        else:
            version = []
            desc = 'all information about package %s.'%cn

        # make sure the user has permission to do stuff
        if not (self.store.has_role('Owner', name) or
                (version and self.store.has_role('Maintainer', name))):
            raise Forbidden, \
                "You are not allowed to edit '%s' package information"%name

        if not self.form.has_key('confirm'):
            content = StringIO.StringIO()
            w = content.write
            w('''
<p>You are about to remove %s
This action <em>cannot be undone</em>!<br>
Are you <strong>sure</strong>?</p>
<form action="%s" method="POST">
<input type="hidden" name=":action" value="remove_pkg">
<input type="hidden" name="name" value="%s">
'''%(desc, self.url_path, cn))
            for v in version:
                v = cgi.escape(v)
                w('<input type="hidden" name="version" value="%s">'%v)

            w('''
<input type="submit" name="confirm" value="OK">
<input type="submit" name="confirm" value="CANCEL">
</form>''')

            return self.success(heading='Confirm removal of %s'%desc,
                content=content.getvalue())

        elif self.form['confirm'].value == 'CANCEL':
            return self.pkg_edit()

        # ok, do it
        if version:
            for v in version:
                self.store.remove_release(name, v)
            self.success(heading='Removed %s'%desc,
                message='Release removed')
        else:
            self.store.remove_package(name)
            self.success(heading='Removed %s'%desc,
                message='Package removed')

    # alias useful for the files ZPT page
    dist_file_types = store.dist_file_types
    def files(self):
        '''List files and handle file submissions.
        '''
        name = version = None
        if self.form.has_key('name'):
            name = self.form['name'].value
        if self.form.has_key('version'):
            version = self.form['version'].value
        if not name or not version:
            self.fail(heading='Name and version are required',
                message='Name and version are required')
            return

        # if allowed, handle file upload
        maintainer = False
        if (self.store.has_role('Maintainer', name) or
                self.store.has_role('Owner', name)):
            maintainer = True
            if self.form.has_key('submit_upload'):
                self.file_upload()

            elif (self.form.has_key('submit_remove') and
                    self.form.has_key('file-ids')):

                fids = self.form['file-ids']
                if isinstance(fids, list):
                    fids = [v.value for v in fids]
                else:
                    fids = [fids.value]

                for digest in fids:
                    self.store.remove_file(digest)

        self.write_template('files.pt', name=name, version=version,
            maintainer=maintainer, title="Files for %s %s"%(name, version))

    def file_upload(self):
        # make sure the user is identified
        if not self.username:
            raise Unauthorised, \
                "You must be identified to edit package information"

        # figure the package name and version
        name = version = None
        if self.form.has_key('name'):
            name = self.form['name'].value
        if self.form.has_key('version'):
            version = self.form['version'].value
        if not name or not version:
            self.fail(heading='Name and version are required',
                message='Name and version are required')
            return

        # make sure the user has permission to do stuff
        if not (self.store.has_role('Owner', name) or
                self.store.has_role('Maintainer', name)):
            raise Forbidden, \
                "You are not allowed to edit '%s' package information"%name

        pyversion = 'source'
        content = filetype = md5_digest = comment = None
        if self.form.has_key('content'):
            content = self.form['content']
        if self.form.has_key('filetype'):
            filetype = self.form['filetype'].value
        if content is None or filetype is None:
            self.fail(heading='Both content and filetype are required',
                message='Both content and filetype are required %r'
                %self.form.keys())
            return

        md5_digest = self.form['md5_digest'].value

        comment = self.form['comment'].value
        
        # python version?
        if self.form['pyversion'].value:
            pyversion = self.form['pyversion'].value
        elif filetype not in (None, 'sdist'):
            self.fail(heading='Python version is required',
                message='Python version is required for binary '
                    'distribution uploads')
            return

        # check for valid filenames
        filename = content.filename
        if not safe_filenames.match(filename):
            self.fail(heading='invalid distribution file',
                message='invalid distribution file')
            return

        # check for dodgy filenames
        if '/' in filename or '\\' in filename:
            self.fail(heading='invalid distribution file',
                message='invalid distribution file')
            return

        # grab content
        content = content.value

        # check for valid exe
        if filename.endswith('.exe'):
            if filetype != 'bdist_wininst':
                self.fail(heading='invalid distribution file',
                    message='invalid distribution file')
                return
            try:
                t = StringIO.StringIO(content)
                t.filename = filename
                z = zipfile.ZipFile(t)
                l = z.namelist()
            except zipfile.error:
                self.fail(heading='invalid distribution file',
                    message='invalid distribution file')
                return
            for zipname in l:
                if not safe_zipnames.match(zipname):
                    self.fail(heading='invalid distribution file',
                        message='invalid distribution file')
                    return
        elif filename.endswith('.zip'):
            # check for valid zip
            try:
                t = StringIO.StringIO(content)
                t.filename = filename
                z = zipfile.ZipFile(t)
                l = z.namelist()
            except zipfile.error:
                self.fail(heading='invalid distribution file',
                    message='invalid distribution file')
                return
            if 'PKG-INFO' not in l:
                self.fail(heading='invalid distribution file',
                    message='invalid distribution file')
                return

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
            filetype, pyversion, comment, filename)

    # 
    # classifiers listing
    #
    def list_classifiers(self):
        ''' Just return the list of classifiers.
        '''
        c = '\n'.join(self.store.get_classifiers())
        self.handler.send_response(200, 'OK')
        self.handler.send_header('Content-Type', 'text/plain')
        self.handler.end_headers()
        self.wfile.write(c + '\n')

    #
    # User handling code (registration, password changing
    #
    def user_form(self):
        ''' Make the user authenticate before viewing the "register" form.
        '''
        if not self.username:
            raise Unauthorised, 'You must authenticate'
        self.register_form()

    def register_form(self):
        ''' Throw up a form for regstering.
        '''
        info = {'name': '', 'password': '', 'confirm': '', 'email': ''}
        if self.username:
            user = self.store.get_user(self.username)
            info['name'] = '<input type="hidden" name="name" value="%s">%s'%(
                urllib.quote(user['name']), cgi.escape(user['name']))
            info['email'] = cgi.escape(user['email'])
            info['action'] = 'Update details'
            info['gpg_keyid'] = cgi.escape(user['gpg_keyid'] or "")
            heading = 'User profile'
            self.nav_current = 'user_form'
        else:
            info['action'] = 'Register'
            info['name'] = '<input name="name">'
            info['gpg_keyid'] = ''
            heading = 'Manual user registration'
            self.nav_current = 'register_form'
        content = '''
<form method="POST">
<input type="hidden" name=":action" value="user">
<table class="form">
<tr><th>Username:</th>
    <td>%(name)s</td>
</tr>
<tr><th>Password:</th>
    <td><input type="password" name="password"></td>
</tr>
<tr><th>Confirm:</th>
    <td><input type="password" name="confirm"></td>
</tr>
<tr><th>Email Address:</th>
    <td><input name="email" value="%(email)s"></td>
</tr>
<tr><th>PGP Key ID:</th>
    <th><input name="gpg_keyid" value="%(gpg_keyid)s"></td>
</tr>
<tr><td>&nbsp;</td><td><input type="submit" value="%(action)s"></td></tr>
</table>
'''%info
        if not self.username:
            content += '''
<p>A confirmation email will be sent to the address you nominate above.</p>
<p>To complete the registration process, visit the link indicated in the
email.</p>'''
        self.success(content=content, heading=heading)

    def user(self):
        ''' Register, update or validate a user.

            This interface handles one of three cases:
                1. completion of rego with One Time Key
                2. new user sending in name, password and email
                3. updating existing user details for currently authed user
        '''
        info = {}
        for param in 'name password email otk confirm gpg_keyid'.split():
            if self.form.has_key(param):
                v = self.form[param].value.strip()
                if v: info[param] = v

        if info.has_key('otk'):
            if self.username is None:
                raise Unauthorised
            # finish off rego
            if info['otk'] != self.store.get_otk(self.username):
                response = 'Error: One Time Key invalid'
            else:
                # OK, delete the key
                self.store.delete_otk(info['otk'])
                response = 'Registration complete'

        elif self.username is None:
            for param in 'name password email confirm'.split():
                if not info.has_key(param):
                    raise FormError, '%s is required'%param

            # validate a complete set of stuff
            # new user, create entry and email otk
            name = info['name']
            if self.store.has_user(name):
                self.fail('user "%s" already exists'%name,
                    heading='User registration')
                return
            if not info.has_key('confirm') or info['password']<>info['confirm']:
                self.fail("password and confirm don't match", heading='Users')
                return
            info['otk'] = self.store.store_user(name, info['password'],
                info['email'], info['gpg_keyid'])
            info['url'] = self.config.url
            info['admin'] = self.config.adminemail
            self.send_email(info['email'], rego_message%info)
            response = 'Registration OK'

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
        self.success(message=response, heading='Users')

    def forgotten_password_form(self):
        ''' Enable the user to reset their password.
        '''
        self.page_head('Python Packages Index: Forgotten Password',
            heading='Request password reset')
        w = self.wfile.write
        w('''
<p>You have two options if you have forgotten your password. If you
know the email address you registered with, enter it below.</p>
<form method="POST">
<input type="hidden" name=":action" value="password_reset">
<table class="form">
<tr><th>Email Address:</th>
    <td><input name="email"></td>
</tr>
<tr><td>&nbsp;</td><td><input type="submit" value="Reset password"></td></tr>
</table>
</form>

<p>Or, if you know your username, then enter it below.</p>

<form method="POST">
<input type="hidden" name=":action" value="password_reset">
<table class="form">
<tr><th>Username:</th>
    <td><input name="name"></td>
</tr>
<tr><td>&nbsp;</td><td><input type="submit" value="Reset password"></td></tr>
</</form>
</table>

<p>A confirmation email will be sent to you - please follow the instructions
within it to complete the reset process.</p>
''')

    def password_reset(self):
        """Reset the user's password and send an email to the address given.
        """
        if self.form.has_key('email') and self.form['email'].value.strip():
            email = self.form['email'].value.strip()
            user = self.store.get_user_by_email(email)
            if user is None:
                self.fail('email address unknown to me')
                return
            pw = ''.join([random.choice(chars) for x in range(10)])
            self.store.store_user(user['name'], pw, user['email'], None)
            info = {'name': user['name'], 'password': pw,
                'email':user['email']}
            info['admin'] = self.config.adminemail
            self.send_email(email, password_message%info)
            self.success(message='Email sent with new password')
        elif self.form.has_key('name') and self.form['name'].value.strip():
            name = self.form['name'].value.strip()
            user = self.store.get_user(name)
            if user is None:
                self.fail('user name unknown to me')
                return
            info = {'name': user['name'], 'email':user['email'],
                'url': self.config.url}
            info['admin'] = self.config.adminemail
            self.send_email(user['email'], password_change_message%info)
            self.success(message='Email sent to confirm password change')
        else:
            self.fail(message='You must supply a username or email address')

    def send_email(self, recipient, message):
        ''' Send an administrative email to the recipient
        '''
        smtp = smtplib.SMTP(self.config.mailhost)
        smtp.sendmail(self.config.adminemail, recipient, message)

    def packageURL(self, name, version):
        ''' return a URL for the link to display a particular package
        '''
        return '%s?:action=display&name=%s&version=%s'%(self.url_path,
            urllib.quote(name), urllib.quote(version))

    def packageLink(self, name, version):
        ''' return a link to display a particular package
        '''
        return '<a href="%s">%s&nbsp;%s</a>'%(self.packageURL(name, version),
            cgi.escape(name), cgi.escape(version))
