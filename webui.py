
import sys, os, urllib, StringIO, traceback, cgi, binascii, getopt
import time, whrandom, smtplib, base64, sha, email, types, stat, urlparse
from distutils.util import rfc822_escape
from xml.sax.saxutils import escape as xmlescape

import store, config, flamenco, trove

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
To: %(email)s

To complete your registration of the user "%(name)s" with the python module
index, please visit the following URL:

  %(url)s?:action=user&otk=%(otk)s

'''

# password change request email
password_change_message = '''Subject: PyPI password change request
To: %(email)s

Someone, perhaps you, has requested that the password be changed for your
username, "%(name)s". If you wish to proceed with the change, please follow
the link below:

  %(url)s?:action=password_reset&email=%(email)s

You should then receive another email with the new password.

'''

# password reset email - indicates what the password is now
password_message = '''Subject: PyPI password has been reset
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
        self.form = cgi.FieldStorage(fp=handler.rfile, environ=env)
        whrandom.seed(int(time.time())%256)
        self.nav_current = None

        (protocol, machine, path, x, x, x) = urlparse.urlparse(self.config.url)
        self.url_machine = '%s://%s'%(protocol, machine)
        self.url_path = path

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
                    content='<pre>%s</pre>'%s)
        finally:
            self.store.close()

    def fail(self, message, title="Python Packages Index", code=400,
            heading=None, headers={}, content=''):
        ''' Indicate to the user that something has failed.
        '''
        self.page_head(title, message, heading, code, headers)
        self.wfile.write('<p class="error">%s</p>'%message)
        self.wfile.write(content)
        self.page_foot()

    def success(self, message=None, title="Python Packages Index",
            code=200, heading=None, headers={}, content=''):
        ''' Indicate to the user that the operation has succeeded.
        '''
        self.page_head(title, message, heading, code, headers)
        if message:
            self.wfile.write('<p class="ok">%s</p>'%message)
        self.wfile.write(content)
        self.page_foot()


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
    def page_head(self, title, message=None, heading=None, code=200,
            headers={}):
        ''' Spit out HTTP and HTML headers.

            "title" is the HTML page title
            "message" is a succint error or success message
            "code" is the HTTP response code
            "heading" is usually a slight variation on "title" and is
                      used in a HTML header
            "headers" is a dictionary of additional HTTP headers to send
        '''
        if not message:
            message = 'OK'
        self.handler.send_response(code, message)
        self.handler.send_header('Content-Type', 'text/html')
        for k,v in headers.items():
            self.handler.send_header(k, v)
        self.handler.end_headers()
        if heading is None: heading = title
        w = self.wfile.write
        banner_num = whrandom.randrange(0,64)
        banner_color = [
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
             ][banner_num]
        w('''\
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<?xml-stylesheet href="http://www.python.org/style.css" type="text/css"?>
<html><head><title>%s</title>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">
<meta name="generator" content="HT2HTML/2.0">
<link rel="SHORTCUT ICON" href="http://www.python.org/pics/pyfav.gif">
<link rel="STYLESHEET" href="http://www.python.org/style.css" type="text/css">
<link rel="STYLESHEET" href="http://www.python.org/css/pypi.css" type="text/css">
<link rel="alternate" type="application/rss+xml" title="RSS: 20 latest updates"
      href="http://www.python.org/pypi?:action=rss">
</head>
<body bgcolor="#ffffff" text="#000000"
      marginwidth="0" marginheight="0"
      link="#0000bb"  vlink="#551a8b"
      alink="#ff0000">
<!-- start of page table -->
<table width="100%%" border="0" cellspacing="0" cellpadding="0">
<!-- start of banner row -->
<tr>
<!-- start of corner cells -->
<td width="150" valign="middle" bgcolor="%s" class="corner">

<center>
    <a href="/">
    <img alt="" border="0"
         src="http://www.python.org/pics/PyBanner%03d.gif"></a></center> </td>
<td width="15" bgcolor="#99ccff">&nbsp;&nbsp;</td>
<td width="90%%" bgcolor="#99ccff" class="banner">
<table width="100%%" border="0" cellspacing="0" cellpadding="0"
       bgcolor="#ffffff">
<tr><td bgcolor="#99ccff"> <a href="/">Home</a> </td>
    <td bgcolor="#99ccff"> <a href="/search/">Search</a> </td>
    <td bgcolor="#99ccff"> <a href="/download/">Download</a> </td>
    <td bgcolor="#99ccff"> <a href="/doc/">Documentation</a> </td>
</tr><tr> <td bgcolor="#99ccff"> <a href="/Help.html">Help</a> </td>
    <td bgcolor="#99ccff"> <a href="/dev/">Developers</a> </td>
    <td bgcolor="#99ccff"> <a href="/psa/">Community</a> </td>
    <td bgcolor="#99ccff"> <a href="/sigs/">SIGs</a> </td>
</tr></table>

</td></tr><!-- end of banner row -->

<tr><!-- start of sidebar/body row -->
<td width="150" valign="top" bgcolor="#99ccff" class="sidebar">
<table width="100%%" border="0" cellspacing="0" cellpadding="3"
       bgcolor="#ffffff">
'''%(title, banner_color, banner_num))

        # add in the navbar
        l = []
        la = l.append
        if self.username:
            u = cgi.escape(self.username).replace(' ', '&nbsp;')
            w('''
<tr><td bgcolor="#003366"><b><font color="#ffffff">
Logged In
</font></b></td></tr>
<tr><td bgcolor="#99ccff">Welcome %s</td></tr>
<tr><td bgcolor="#99ccff">
 <a href="%s?:action=user_form">Your details</a></td></tr>
<tr><td bgcolor="#99ccff">
 <a href="%s?:action=logout">Logout</a></td></tr>
'''%(u, self.url_path, self.url_path))
            packages = self.store.user_packages(self.username)
            if packages:
                w('''
<tr><td bgcolor="#003366"><b><font color="#ffffff">
Your Packages
</font></b></td></tr>
''')
                for name, in packages:
                    un = urllib.quote(name)
                    w('''<tr><td bgcolor="#99ccff">
 <a href="%s?:action=pkg_edit&name=%s">%s</a></td></tr>\n'''%(self.url_path, un,
                        name))

        else:
            w('''
<tr><td bgcolor="#003366"><b><font color="#ffffff">
Not Logged In
</font></b></td></tr>
<tr><td bgcolor="#99ccff">
 <a href="%s?:action=register_form">Register</a></td></tr>
<tr><td bgcolor="#99ccff">
 <a href="%s?:action=login">Login</a></td></tr>
'''%(self.url_path, self.url_path))
        w('''
<tr><td bgcolor="#99ccff">&nbsp;</td></tr>
<tr><td bgcolor="#003366"><b><font color="#ffffff">
PyPI Actions
</font></b></td></tr>
<tr><td bgcolor="#99ccff">
''')
        for k, v in self.navlinks:
            v = v.replace(' ', '&nbsp;')
            if k == self.nav_current:
                la('<strong>%s</strong>'%v)
            elif k == 'role_form':
                if self.username and self.store.has_role('Admin', ''):
                    la('<a href="%s?:action=%s">%s</a>'%(self.url_path, k, v))
            else:
                la('<a href="%s?:action=%s">%s</a>'%(self.url_path, k, v))
        w('</td></tr>\n<tr><td bgcolor="#99ccff">'.join(l))

        w('''
</td></tr>
<tr><td bgcolor="#99ccff">&nbsp;</td></tr>
<tr><td bgcolor="#003366"><b><font color="#ffffff"> Contact Us
</font></b></td></tr>

<tr><td bgcolor="#99ccff">
<a href="http://sourceforge.net/projects/pypi/">Bug reports</a>
</td></tr>
<tr><td bgcolor="#99ccff">
<a href="http://sourceforge.net/projects/pypi/">Support requests</a>
</td></tr>
<tr><td bgcolor="#99ccff">
<a href="http://www.python.org/sigs/catalog-sig/">Comments</a>
</td></tr>

<tr><td bgcolor="#99ccff"> &nbsp; </td></tr>
<tr><td bgcolor="#99ccff"> <a href="/"><img align="center" alt="" border="0"
         src="http://www.python.org/pics/PythonPoweredSmall.gif"></a></td></tr>
<tr><td bgcolor="#99ccff"> &nbsp; </td></tr>
<tr><td bgcolor="#99ccff"> &copy; 2003 </td></tr>
<tr><td bgcolor="#99ccff">
<a href="http://www.python.org/psf/">Python Software Foundation</a>
</td></tr>
</table><!-- end of sidebar table -->

</td>
<td width="15">&nbsp;</td><!--spacer-->

<!-- begin body -->
<td bgcolor="white" valign="top"><h1 align="left">PyPI: %s</h1>
'''%heading)


    def page_foot(self):
        self.wfile.write('''

</td> </tr> </table>
</body></html>
''')
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
        if action in 'home browse rss submit submit_pkg_info remove_pkg pkg_edit verify submit_form display display_pkginfo search_form register_form user_form forgotten_password_form user password_reset index search role role_form list_classifiers login logout'.split():
            getattr(self, action)()
        else:
            raise ValueError, 'Unknown action'

        # commit any database changes
        self.store.commit()

    def home(self, nav_current='home'):
        content = StringIO.StringIO()
        w = content.write
        w('''
<p>
Welcome to the Python Package Index (PyPI).
</p>
<p><strong>Tip of the week:</strong> 
If you have submitted newer versions of a package to PyPI, you may hide the
older versions from browsing and listing. Simply log in and select the package
from the <strong>Your Packages</strong> menu on the left, then set the older
version <strong>Hide?</strong> flag to <strong>Yes</strong>.
</p>
<p>
You may:
</p>
<ul>
<li><a href="%s?:action=search_form">Search</a>
<li><a href="%s?:action=browse">Browse the tree of packages</a>
<li><a href="%s?:action=index">View a flat list of all packages</a>
<li><a href="%s?:action=submit_form">Submit package information</a> (note that
you must <a href="%s?:action=register_form">register to submit</a>)
</ul>

<p>Last 20 updates:</p>
<table class="list">
<tr><th>Updated</th><th>Package</th><th>Description</th></tr>
'''%(self.url_path, self.url_path, self.url_path, self.url_path, self.url_path))
        i=0
        for name, version, date, summary in self.store.latest_updates():
            w('''<tr%s>
        <td>%s</td>
        <td>%s</td>
        <td>%s</td></tr>'''%((i/3)%2 and ' class="alt"' or '', date[:10],
                self.packageLink(name, version), cgi.escape(str(summary))))
            i+=1
        w('''
<tr><td id="last" colspan="3">&nbsp;</td></tr>
</table>
''')
        self.success(heading='Home', content=content.getvalue())

    def rss(self):
        """Dump the last N days' updates as an RSS feed.
        """
        # determine whether the rss file is up to date
        rss_file = os.path.join(os.path.split(self.config.database)[0],
            'rss.xml')
        if not os.path.exists(rss_file):
            self.rss_regen(rss_file)
        else:
            rss_mtime = os.stat(rss_file)[stat.ST_MTIME]
            if rss_mtime < self.store.last_modified:
                self.rss_regen(rss_file)

        # TODO: throw in a last-modified header too?
        self.handler.send_response(200, 'OK')
        self.handler.send_header('Content-Type', 'text/xml')
        self.handler.end_headers()
        self.wfile.write(open(rss_file).read())

    def rss_regen(self, rss_file):
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
        for name, version, date, summary in self.store.latest_updates():
            date = date.replace(' ','T')
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

        tree = trove.Trove(self.store.getCursor())
        qs = os.environ.get('QUERY_STRING', '')
        l = [x for x in cgi.parse_qsl(qs) if not x[0].startswith(':')]
        q = flamenco.Query(self.store.getCursor(), tree, l)

        # do the query
        matches, choices = q.list_choices()

        # format the result
        if q.query:
            w('<p>Current query:<br>')
            for fld, value in q.query:
                n = q.trove[value]
                newq = q.copy()
                newq.remove_field(fld, value)
                w(cgi.escape(n.path))
                w(' <a href="%s?:action=browse&%s">[ignore]</a><br>\n'%(
                    self.url_path, newq.as_href()))
        else:
            w('<p>Currently querying everything')

        w('</p>')
        if q.query and matches:
            w('<table class="list">')
            w('<tr><th>Package</th><th>Description</th></tr>')
            i=0
            for summary, name, version in matches:
                w('''<tr%s>
        <td>%s</td>
        <td>%s</td></tr>'''%((i/3)%2 and ' class="alt"' or '',
                self.packageLink(name, version), cgi.escape(str(summary))))
                i+=1
            w('''
<tr><td id="last" colspan="2">&nbsp;</td></tr>
</table>
''')
        else:
            w('<p>Number of matches: %i</p>\n'%len(matches))
        w('<hr>\n')

        choices.sort()
        for field, header, options, exist_value in choices:
            if len(options) == 0:
                continue
            w('<div>')
            w('<strong>%s</strong><br>'%cgi.escape(header))
            options.sort()
            l = []
            for text, node_id, count in options:
                newq = q.copy()
                newq.set_field(field, exist_value, node_id)
                l.append('<a href="%s?:action=browse&%s">%s</a> (%i)'%(
                    self.url_path, newq.as_href(), cgi.escape(text), count))
            w(' / \n'.join(l))
            w("</div>")

        self.success(heading='Browsing', content=content.getvalue())

    def index(self, nav_current='index'):
        ''' Print up an index page
        '''
        self.nav_current = nav_current
        content = StringIO.StringIO()
        w = content.write
        w('<table class="list">\n')
        w('<tr><th>Package</th><th>Description</th></tr>\n')
        spec = self.form_metadata()
        if not spec.has_key('_pypi_hidden'):
            spec['_pypi_hidden'] = '0'
        i=0
        for pkg in self.store.query_packages(spec):
            name = pkg['name']
            version = pkg['version']
            w('''<tr%s>
        <td>%s</td>
        <td>%s</td></tr>'''%((i/3)%2 and ' class="alt"' or '',
                self.packageLink(name, version),
                cgi.escape(str(pkg['summary']))))
            i+=1
        w('''
<tr><td id="last" colspan="3">&nbsp;</td></tr>
</table>
''')
        self.success(heading='Index of packages', content=content.getvalue())

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
        self.nav_current = 'search_form'
        self.page_head('Search')
        self.wfile.write('''
<form method="GET" action="%s">
<input type="hidden" name=":action" value="search">
<table class="form">
<tr><th>Name:</th>
    <td><input name="name"></td>
</tr>
<tr><th>Version:</th>
    <td><input name="version"></td>
</tr>
<tr><th>Summary:</th>
    <td><input name="summary"></td>
</tr>
<tr><th>Description:</th>
    <td><input name="description"></td>
</tr>
<tr><th>Keywords:</th>
    <td><input name="keywords"></td>
</tr>

<tr><th>Hidden:</th>
    <td><select name="_pypi_hidden">
         <option value="0">No</option>
         <option value="1">Yes</option>
         <option value="">Don\'t Care</option>
        </select></td>
</tr>
<tr><td>&nbsp;</td><td><input type="submit" value="Search"></td></tr>
</table>
</form>
'''%self.url_path)
        self.page_foot()

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
            s = '\n'.join(['<option value="%s">%s</option>'%(
                cgi.escape(x['name']),
                cgi.escape(x['name'])) for x in self.store.get_packages()])
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
            l.append('<tr><td>%s</td><td>%s</td></tr>'%(
                cgi.escape(assignment['user_name']),
                cgi.escape(assignment['role_name'])))
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
            # make sure if the user has the role, and is the current user
            # and the role is Owner, that we can't do this!
            if self.username == user_name and role_name == 'Owner':
                raise FormError, "sanity: can't remove own Owner Role"
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
            value = info.get(key)
            if not value:
                continue

            label = key.capitalize().replace('_', '-')

            if key == 'description':
                value = rfc822_escape(value)

            w('%s: %s\n' % (label, value))

        # Classifiers aren't PEP 241, but PEP 301 suggests they be in
        # metadata files.
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

    def display(self, name=None, version=None, ok_message=None,
            error_message=None):
        ''' Print up an entry
        '''
        content = StringIO.StringIO()
        w = content.write

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
        # top links
        un = urllib.quote(name)
        uv = urllib.quote(version)
        w('<br>Package: ')
        w('<a href="%s?:action=role_form&package_name=%s">admin</a>\n'%(
            self.url_path, un))
        w('| <a href="%s?:action=submit_form&name=%s&version=%s"'
            '>edit</a>'%(self.url_path, un, uv))
        w('| <a href="%s?:action=display_pkginfo&name=%s&version=%s"'
            '>PKG-INFO</a>'%(self.url_path, un, uv))
        w('<br>')

        # now the package info
        w('<table class="form">\n')
        keys = info.keys()
        keys.sort()
        keypref = 'name version author author_email maintainer maintainer_email home_page download_url summary license description keywords platform'.split()
        for key in keypref:
            if not info.has_key(key): continue
            value = info[key]
            if not value: continue
            if key == 'download_url':
                label = "Download URL"
            else:
                label = key.capitalize().replace('_', ' ')
            if (key in ('download_url', 'url', 'home_page')
                    and value != 'UNKNOWN'):
                w('<tr><th nowrap>%s: </th><td><a href="%s">%s</a></td></tr>\n'%(label,
                    value, cgi.escape(value)))
            elif key == 'description':
                w('<tr><th nowrap>%s: </th><td><pre>%s</pre></td></tr>\n'%(
                    label, cgi.escape(value)))
            elif key.endswith('_email'):
                value = cgi.escape(value)
                value = value.replace('@', ' at ')
                value = value.replace('.', ' ')
                w('<tr><th nowrap>%s: </th><td>%s</td></tr>\n'%(label, value))
            else:
                w('<tr><th nowrap>%s: </th><td>%s</td></tr>\n'%(label,
                    cgi.escape(value)))

        classifiers = self.store.get_release_classifiers(name, version)
        if classifiers:
            w('<tr><th>Classifiers: </th><td>')
            w('\n<br>'.join([cgi.escape(x) for x in classifiers]))
            w('\n</td></tr>\n')
        w('\n</table>\n')

        # package's role assignments
        w(self.package_role_list(name))

        # package's journal
        w('<table class="history">\n')
        w('<tr><th colspan=4 class="header">Journal</th></tr>\n')
        w('<tr><th>Date</th><th>User</th><th>Action</th></tr>\n')
        for entry in self.store.get_journal(name, version):
            w('<tr><td nowrap>%s</td><td>%s</td><td>%s</td></tr>\n'%(
                entry['submitted_date'], entry['submitted_by'],
                entry['action']))
        w('\n</table>\n')

        if error_message:
            self.fail(error_message,
                heading='%s %s'%(name, version),
                content=content.getvalue())
        else:
            self.success(message=ok_message,
                heading='%s %s'%(name, version),
                content=content.getvalue())

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
                a = value=='0' and ' selected' or ''
                b = value=='1' and ' selected' or ''
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
            # clean up the keys and values
            k = k.lower()
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
            data['_pypi_hidden'] = '0'

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
            if type(v) == type([]):
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

        # make sure the user has permission to do stuff
        if not (self.store.has_role('Owner', name) or
                self.store.has_role('Maintainer', name)):
            raise Forbidden, \
                "You are not allowed to edit '%s' package information"%name

        releases = self.store.get_package_releases(name)
        reldict = {}
        for release in releases:
            info = {}
            for k,v in release.items():
                info[k] = v
            reldict[info['version']] = info

        content = StringIO.StringIO()
        w = content.write

        # see if we're editing
        for key in self.form.keys():
            if key.startswith('hid_'):
                ver = key[4:]
                info = reldict[ver]
                info['_pypi_hidden'] = self.form[key].value
            elif key.startswith('sum_'):
                ver = key[4:]
                info = reldict[ver]
                info['summary'] = self.form[key].value

        # update the database
        for version, info in reldict.items():
            self.store.store_package(name, version, info)

        # now display
        un = urllib.quote(name)
        cn = cgi.escape(name)
        url = self.url_path
        w('''
<p>
  Each package may have a release for each version of the
  package that is released. You may use this form to hide releases
  from users.
</p>
<p><a href="%s?:action=role_form&package_name=%s">Role admin</a></p>
<p><a href="%s?:action=remove_pkg&name=%s">Remove package</a></p>
<form method="POST">
<input type="hidden" name=":action" value="pkg_edit">
<input type="hidden" name="name" value="%s">
'''%(self.url_path, un, self.url_path, un, cn))

        w('''<table class="list" style="width: auto">
   <tr><th>Version</th><th>Hide?</th><th>Summary</th><th colspan="3">Actions</th></tr>''')
        for release in releases:
            release = reldict[release['version']]
            uv = urllib.quote(release['version'])
            cv = cgi.escape(release['version'])
            selname = 'hid_' + uv
            selyes = selno = ''
            if release['_pypi_hidden'] == '1':
                selyes = ' selected'
            else:
                selno = ' selected'
            sumname = 'sum_' + uv
            summary = cgi.escape(release['summary'])
            w('''<tr><td>%(cv)s</td>
  <td>
   <select name="%(selname)s">
    <option value="0"%(selno)s>No</option>
    <option value="1"%(selyes)s>Yes</option>
   </select>
  </td>
  <td><input size="40" name="%(sumname)s" value="%(summary)s"></td>
  <td><a href="%(url)s?:action=display&name=%(un)s&version=%(uv)s">show</td>
  <td><a href="%(url)s?:action=submit_form&name=%(un)s&version=%(uv)s">edit</td>
  <td><a href="%(url)s?:action=remove_pkg&name=%(un)s&version=%(uv)s">remove</td></tr>
'''%locals())
        w('''<tr><td id="last" colspan="6">
   <input type="submit" value="Update Releases"</td></tr></table>
</form>''')

        self.success(heading='Package %s'%cn, content=content.getvalue())

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
            version = self.form['version'].value
            cv = cgi.escape(version)
            desc = 'release %s of package %s.'%(cv, cn)
        else:
            version = None
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
<form>
<input type="hidden" name=":action" value="remove_pkg">
<input type="hidden" name="name" value="%s">
'''%(desc, cn))
            if version:
                w('<input type="hidden" name="version" value="%s">'%cv)

            w('''
<input type="submit" name="confirm" value="OK">
<input type="submit" name="confirm" value="CANCEL">
</form>''')

            return self.success(heading='Confirm removal of %s'%desc,
                content=content.getvalue())

        elif self.form['confirm'].value == 'CANCEL':
            return self.pkg_edit()

        # ok, do it
        if self.form.has_key('version'):
            self.store.remove_release(name, version)
            self.success(heading='Removed %s'%desc,
                message='Release removed')
        else:
            self.store.remove_package(name)
            self.success(heading='Removed %s'%desc,
                message='Package removed')


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
            heading = 'User profile'
            self.nav_current = 'user_form'
        else:
            info['action'] = 'Register'
            info['name'] = '<input name="name">'
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
                1. new user sending in name, password and email
                2. completion of rego with One Time Key
                3. updating existing user details for currently authed user
        '''
        info = {}
        for param in 'name password email otk confirm'.split():
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
                info['email'])
            info['url'] = self.config.url
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
            self.store.store_user(self.username, password, email)
            response = 'Details updated OK'
        self.success(message=response, heading='Users')

    def forgotten_password_form(self):
        ''' Enable the user to reset their password.
        '''
        self.page_head('Forgotten Password',
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
            pw = ''.join([whrandom.choice(chars) for x in range(10)])
            self.store.store_user(user['name'], pw, user['email'])
            info = {'name': user['name'], 'password': pw,
                'email':user['email']}
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
        ''' return a URL for the link to display a particular package
        '''
        return '<a href="%s">%s %s</a>'%(self.packageURL(name, version),
            cgi.escape(name), cgi.escape(version))
