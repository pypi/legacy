
import sys, os, urllib, StringIO, traceback, cgi, binascii, getopt
import time, whrandom, smtplib, base64, sha, email, types

import store, config

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
<p>If you are a new user, <a href="?:action=register_form">please
register</a>.</p>
<p>If you have forgotten your password, you can have it
<a href="?:action=forgotten_password_form">reset for you</a>.</p>
'''

chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'

class WebUI:
    ''' Handle a request as defined by the "env" parameter. "handler" gives
        access to the user via rfile and wfile, and a few convenience
        functions (see pypi.cgi).

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

    def run(self):
        ''' Run the request, handling all uncaught errors and finishing off
            cleanly.
        '''
        self.store = store.Store(self.config)
        self.store.open()
        try:
            try:
                self.inner_run()
            except NotFound:
                self.fail('Not Found', code=404)
            except Unauthorised, message:
                message = str(message)
                if not message:
                    message = 'You must login to access this feature'
                self.fail(message, code=401, heading='Login required',
                    content=unauth_message, headers={'WWW-Authenticate':
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
        ('index', 'index'),
        ('search_form', 'search'),
        ('submit_form', 'package submission'),
        ('user_form', 'edit your details'),
        ('register_form', 'register for a login'),
        ('list_classifiers', 'list trove classifiers'),
        ('role_form', 'admin'),
        ('login', 'login'),
        ('logout', 'logout')
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
        w('''
<html><head><title>TEST PyPI: %s</title>
<link rel="stylesheet" type="text/css" href="http://mechanicalcat.net/pypi.css">
</head>
<body>
<div id="header"><h1 align="left">TEST PyPI: %s</h1></div>
<div id="navbar">
'''%(title, heading))

        if self.username:
            w('<em>logged in as %s</em>'%self.username)
        else:
            w('<em>you are anonymous</em>')
        for k, v in self.navlinks:
            if k == self.nav_current:
                w('<strong>%s</strong>'%v)
            elif k in ('login', 'register_form'):
                if not self.username:
                    w('<a href="?:action=%s">%s</a>'%(k, v))
            elif k in ('logout', 'user_form'):
                if self.username:
                    w('<a href="?:action=%s">%s</a>'%(k, v))
            elif k == 'role_form':
                if self.username and self.store.has_role('Admin', ''):
                    w('<a href="?:action=%s">%s</a>'%(k, v))
            else:
                w('<a href="?:action=%s">%s</a>'%(k, v))

        w('\n</div><div id="content">\n')

    def page_foot(self):
        self.wfile.write('\n</div>\n</body></html>\n')

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
            action = 'index'

        # make sure the user has permission
        if action in ('submit', ):
            if self.username is None:
                raise Unauthorised
            if self.store.get_otk(self.username):
                raise Unauthorised

        # handle the action
        if action in 'submit submit_pkg_info verify submit_form display search_form register_form user_form forgotten_password_form user password_reset index role role_form list_classifiers login logout'.split():
            getattr(self, action)()
        else:
            raise ValueError, 'Unknown action'

        # commit any database changes
        self.store.commit()

    def index(self):
        ''' Print up an index page
        '''
        self.nav_current = 'index'
        content = StringIO.StringIO()
        w = content.write
        w('<table class="list">\n')
        w('<tr><th>Package</th><th>Release</th><th>Description</th></tr>\n')
        spec = self.form_metadata()
        if not spec.has_key('hidden'):
            spec['hidden'] = '0'
        for pkg in self.store.query_packages(spec):
            name = pkg['name']
            version = pkg['version']
            w('''<tr>
        <td>%s</td>
        <td><a href="?:action=display&name=%s&version=%s">%s</a></td>
        <td>%s</td></tr>'''%(name, urllib.quote(name), urllib.quote(version),
                version, cgi.escape(pkg['summary'])))
        w('''
</table>
<hr>
Author: Richard Jones<br>
Comments to <a href="http://www.python.org/sigs/catalog-sig/">catalog-sig</a>, please.
''')
        self.success(heading='Index of packages', content=content.getvalue())

    def logout(self):
        raise Unauthorised
    def login(self):
        if not self.username:
            raise Unauthorised
        self.index()

    def search_form(self):
        ''' A form used to generate filtered index displays
        '''
        self.page_head('Search')
        self.nav_current = 'search_form'
        self.wfile.write('''
<form method="GET">
<input type="hidden" name=":action" value="index">
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
<tr><th>Long Description:</th>
    <td><input name="long_description"></td>
</tr>
<tr><th>Keywords:</th>
    <td><input name="keywords"></td>
</tr>

<tr><th>Hidden:</th>
    <td><select name="hidden">
         <option value="0">No</option>
         <option value="1">Yes</option>
         <option value="">Don't Care</option>
        </select></td>
</tr>
<tr><td>&nbsp;</td><td><input type="submit" value="Search"></td></tr>
</table>
</form>
''')
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
    <td><input type="hidden" name="package_name" value="%s">%s</td>
</tr>
'''%(urllib.quote(package_name), cgi.escape(package_name))
        elif not self.store.has_role('Admin', ''):
            raise Unauthorised
        else:
            s = '\n'.join(['<option value="%s">%s</option>'%(x['name'],
                x['name']) for x in self.store.get_packages()])
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
        self.success(heading='Role maintenance', content=s)

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
            if self.store.has_role(role_name, package_name, user_name):
                raise FormError, 'user has that role already'
            self.store.add_role(user_name, role_name, package_name)
            message = 'Role Added OK'
        else:
            self.store.delete_role(user_name, role_name, package_name)
            message = 'Role Removed OK'

        self.success(message=message, heading='Role maintenance')

    def display(self, ok_message=None, error_message=None):
        ''' Print up an entry
        '''
        content = StringIO.StringIO()
        w = content.write

        # get the appropriate package info from the database
        name = self.form['name'].value
        version = self.form['version'].value
        info = self.store.get_package(name, version)
        # top links
        un = urllib.quote(name)
        uv = urllib.quote(version)
        w('<br>Package: ')
        w('<a href="?:action=role_form&package_name=%s">admin</a>\n'%un)
        w('| <a href="?:action=submit_form&name=%s&version=%s"'
            '>edit</a>'%(un, uv))
        w('<br>')

        # now the package info
        w('<table class="form">\n')
        keys = info.keys()
        keys.sort()
        for key in keys:
            value = info[key]
            if value is None:
                value = ''
            label = key.capitalize().replace('_', ' ')
            if key in ('url', 'home_page') and value != 'UNKNOWN':
                w('<tr><th nowrap>%s: </th><td><a href="%s">%s</a></td></tr>\n'%(label,
                    value, cgi.escape(value)))
            else:
                w('<tr><th nowrap>%s: </th><td>%s</td></tr>\n'%(label,
                    cgi.escape(value)))

        classifiers = self.store.get_release_classifiers(name, version)
        if classifiers:
            w('<tr><th>Classifiers: </th><td>')
            w('\n<br>'.join([cgi.escape(x) for x in classifiers]))
            w('\n</td></tr>\n')
        w('\n</table>\n')

        # package's journal
        w('<table class="history">\n')
        w('<tr><th colspan=4 class="header">Journal</th></tr>\n')
        w('<tr><th>Date</th><th>User</th><th>IP Address</th><th>Action</th></tr>\n')
        for entry in self.store.get_journal(name, version):
            w('<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n'%(
                entry['submitted_date'], entry['submitted_by'],
                entry['submitted_from'], entry['action']))
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
<p id="submitheader">1. Use the new distutils command:</p>
<ol>
<li>Copy <a href="http://mechanicalcat.net/tech/pypi/register.py">register.py</a> to your
python lib "distutils/command" directory (typically something like
"/usr/lib/python2.1/distutils/command/").
<li>Run "setup.py register" as you would normally run "setup.py" for your
distribution - this will register your distribution's metadata with the
index.
<li>... that's <em>it</em>
</ol>

<p id="submitheader">2. Upload your PKG-INFO file (generated by distutils) here:</p>
<form method="POST" enctype="multipart/form-data">
<input type="hidden" name=":action" value="submit_pkg_info">
<table class="form">
<tr><th>PKG-INFO file:</th>
    <td><input size="40" type="file" name="pkginfo"></td>
</tr>
<tr><td>&nbsp;</td><td><input type="submit" value="Add Package Info"></td></tr>
</table>
</form>

<p id="submitheader">3. Or, enter the information manually:</p>
<form method="POST">
<input type="hidden" name=":action" value="submit">
<table class="form">
''')

        # display all the properties
        for property in 'name version author author_email maintainer maintainer_email home_page license summary description long_description keywords platform download_url hidden'.split():
            # get the existing entry
            if self.form.has_key(property):
                value = self.form[property].value
            else:
                value = info.get(property, '')
            if value is None:
                value = ''

            # form field
            if property == 'hidden':
                a = value=='0' and ' selected' or ''
                b = value=='1' and ' selected' or ''
                field = '''<select name="hidden">
                            <option value="0"%s>No</option>
                            <option value="1"%s>Yes</option>
                           </select>'''%(a,b)
            elif property.endswith('description'):
                field = '<textarea name="%s" rows="5" cols="80">%s</textarea>'%(
                    property, value)
            else:
                field = '<input size="40" name="%s" value="%s">'%(property, value)

            # now spit out the form line
            label = property.replace('_', ' ').capitalize()
            if label in ('Name', 'Version'):
                req = 'class="required"'
            else:
                req = ''
            w('<tr><th %s>%s:</th><td>%s</td></tr>'%(req, label, field))

        w('''
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
                    data[k] = [v]
            else:
                data[k] = v

        # flatten platforms into one string
        platform = data.get('platform', '')
        if isinstance(platform, types.ListType):
            data['platform'] = ','.join(data['platform'])

        # rename classifiers
        if data.has_key('classifier'):
            data['classifiers'] = data['classifier']

        # validate the data
        try:
            self.validate_metadata(data)
        except ValueError, message:
            raise FormError, message

        name = data['name']
        version = data['version']

        # don't hide by default
        if not data.has_key('hidden'):
            data['hidden'] = '0'

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

        # make sure the hidden flag is set
        if not data.has_key('hidden'):
            data['hidden'] = '0'

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
                self.fail("password and confirm don't match",
                    heading='Users')
                return
            info['otk'] = self.store.store_user(name, info['password'],
                info['email'])
            info['url'] = self.config.url
            self.send_email(info['email'], rego_message%info)
            response = 'Registration OK'

        else:
            # update details
            user = self.store.get_user(self.username)
            password = info.get('password', user['password'])
            if info.has_key('confirm') and password != info['confirm']:
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
        ''' Reset the user's password and send an email to the address given.
        '''
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

