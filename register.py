"""distutils.command.register

Implements the Distutils 'register' command (register with the repository).
"""

# created 2002/10/21, Richard Jones

__revision__ = "$Id$"

import sys, os, string, urllib2, getpass, urlparse
import StringIO, ConfigParser

from distutils.core import Command
from distutils.errors import *

class register(Command):

    description = "register the distribution with the repository"

    #DEFAULT_REPOSITORY = 'http://mechanicalcat.net/cgi-bin/pypi.cgi'
    DEFAULT_REPOSITORY = 'http://localhost/cgi-bin/pypi.cgi'
    #DEFAULT_REPOSITORY = 'http://www.amk.ca/cgi-bin/pypi.cgi'

    user_options = [
        ('repository=', 'r',
         "url of repository [default: %s]"%DEFAULT_REPOSITORY),
        ('verify', None,
         'verify the package metadata for correctness'),
        ]
    boolean_options = ['verify']

    def initialize_options(self):
        self.repository = None
        self.verify = 0

    def finalize_options(self):
        if self.repository is None:
            self.repository = self.DEFAULT_REPOSITORY

    def run(self):
        self.check_metadata()
        if self.verify:
            self.verify_metadata()
        else:
            self.send_metadata()

    def check_metadata(self):
        """Ensure that all required elements of meta-data (name, version,
           URL, (author and author_email) or (maintainer and
           maintainer_email)) are supplied by the Distribution object; warn if
           any are missing.
        """
        metadata = self.distribution.metadata

        missing = []
        for attr in ('name', 'version', 'url'):
            if not (hasattr(metadata, attr) and getattr(metadata, attr)):
                missing.append(attr)

        if missing:
            self.warn("missing required meta-data: " +
                      string.join(missing, ", "))

        if metadata.author:
            if not metadata.author_email:
                self.warn("missing meta-data: if 'author' supplied, " +
                          "'author_email' must be supplied too")
        elif metadata.maintainer:
            if not metadata.maintainer_email:
                self.warn("missing meta-data: if 'maintainer' supplied, " +
                          "'maintainer_email' must be supplied too")
        else:
            self.warn("missing meta-data: either (author and author_email) " +
                      "or (maintainer and maintainer_email) " +
                      "must be supplied")

    def verify_metadata(self):
        ''' Send the metadata to the package index server to be checked.

            Doesn't require a login.
        '''
        # figure the data to send - the metadata plus some additional
        # information used by the package server
        meta = self.distribution.metadata
        data = {
            ':action': 'verify',
            'metadata-version' : '1.0',
            'name': meta.get_name(),
            'version': meta.get_version(),
            'summary': meta.get_description(),
            'home-page': meta.get_url(),
            'author': meta.get_contact(),
            'author-email': meta.get_contact_email(),
            'license': meta.get_licence(),
            'description': meta.get_long_description(),
            'keywords': meta.get_keywords(),
            'platform': meta.get_platforms(),
        }

        # send the info to the server and report the result
        (code, result) = self.post_to_server(data)
        print 'Server response (%s): %s'%(code, result)

    def send_metadata(self):
        ''' Send the metadata to the package index server.

            Well, do the following:
            1. figure who the user is, and then
            2. send the data as a Basic auth'ed POST.

            First we try to read the username/password from 
            $HOME/.pythonpackagerc, which is a ConfigParser-formatted
            file with a section [server-login] containing username and
            password entries (both in clear text). Eg:

                [server-login]
                username: fred
                password: sekrit

            Otherwise, to figure who the user is, we offer the user three
            choices:

             1. use existing login,
             2. register as a new user, or
             3. set the password to a random string and email the user.

        '''
        choice = 'x'
        username = password = ''

        # see if we can short-cut and get the username/password from the
        # config
        if os.environ.has_key('HOME'):
            rc = os.path.join(os.environ['HOME'], '.pythonpackagerc')
            if os.path.exists(rc):
                config = ConfigParser.ConfigParser()
                config.read(rc)
                username = config.get('server-login', 'username')
                password = config.get('server-login', 'password')
                choice = '1'

        # get the user's login info
        while choice not in '1234':
            print '''We need to know who you are, so please choose either:
 1. use your existing login,
 2. register as a new user,
 3. have the server generate a new password for you (and email it to you), or
 4. quit
Your selection [default 1]: ''',
            choice = raw_input()
            if choice not in '1234':
                print 'Please choose one of the four options!'

        if choice == '1':
            # get the username and password
            while not username:
                username = raw_input('Username: ')
            while not password:
                password = getpass.getpass('Password: ')

            # set up the authentication
            auth = urllib2.HTTPPasswordMgr()
            host = urlparse.urlparse(self.repository)[1]
            auth.add_password('python packages index', host,
                username, password)

            # figure the data to send - the metadata plus some additional
            # information used by the package server
            meta = self.distribution.metadata
            data = {
                ':action': 'submit',
                'metadata-version' : '1.0',
                'name': meta.get_name(),
                'version': meta.get_version(),
                'summary': meta.get_description(),
                'home-page': meta.get_url(),
                'author': meta.get_contact(),
                'author-email': meta.get_contact_email(),
                'license': meta.get_licence(),
                'description': meta.get_long_description(),
                'keywords': meta.get_keywords(),
                'platform': meta.get_platforms(),
            }

            # send the info to the server and report the result
            (code, result) = self.post_to_server(data, auth)
            print 'Server response (%s): %s'%(code, result)
        elif choice == '2':
            data = {':action': 'user'}
            data['name'] = data['password'] = data['email'] = ''
            data['confirm'] = None
            while not data['name']:
                data['name'] = raw_input('Username: ')
            while data['password'] != data['confirm']:
                while not data['password']:
                    data['password'] = getpass.getpass('Password: ')
                while not data['confirm']:
                    data['confirm'] = getpass.getpass(' Confirm: ')
                if data['password'] != data['confirm']:
                    data['password'] = ''
                    data['confirm'] = None
                    print "Password and confirm don't match!"
            while not data['email']:
                data['email'] = raw_input('   EMail: ')
            (code, result) = self.post_to_server(data)
            if result != 'Registration OK':
                print 'Server response (%s): %s'%(code, result)
            else:
                print 'You will receive an email shortly.'
                print 'Follow the instructions in it to complete registration.'
        elif choice == '3':
            data = {':action': 'password_reset'}
            data['email'] = ''
            while not data['email']:
                data['email'] = raw_input('Your email address: ')
            (code, result) = self.post_to_server(data)
            print 'Server response (%s): %s'%(code, result)

    def post_to_server(self, data, auth=None):
        ''' Post a query to the server, and return a string response.
        '''
        # Build up the MIME payload for the urllib2 POST
        boundary = '--------------GHSKFJDLGDS7543FJKLFHRE75642756743254'
        sep_boundary = '\n--' + boundary
        end_boundary = sep_boundary + '--'
        body = StringIO.StringIO()
        for key, value in data.items():
            # handle multiple entries for the same name
            if type(value) != type([]):
                value = [value]
            for value in value:
                body.write(sep_boundary)
                body.write('\nContent-Disposition: form-data; name="%s"'%key)
                body.write("\n\n")
                body.write(str(value))
                if value and value[-1] == '\r':
                    body.write('\n')  # write an extra newline (lurve Macs)
        body.write(end_boundary)
        body.write("\n")
        body = body.getvalue()

        # build the Request
        headers = {
            'Content-type': 'multipart/form-data; boundary=%s'%boundary,
            'Content-length': str(len(body))
        }
        req = urllib2.Request(self.repository, body, headers)

        # handle HTTP and include the Basic Auth handler
        opener = urllib2.build_opener(
            urllib2.HTTPBasicAuthHandler(password_mgr=auth)
        )
        try:
            result = opener.open(req)
        except urllib2.HTTPError, e:
            if e.headers.has_key('x-pypi-reason'):
                reason = e.headers['x-pypi-reason']
                if reason == 'error':
                    return 'fail', e.fp.read()
                else:
                    return 'fail', reason
            else:
                return 'fail', e.fp.read()
        except urllib2.URLError, e:
            return 'fail', str(e)

        return result.headers['x-pypi-status'], result.headers['x-pypi-reason']

