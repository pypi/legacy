#import logging
#logging.basicConfig(level=logging.DEBUG)

import requests
from requests.auth import OAuth1
from urlparse import parse_qs

CONSUMER_KEY = u'sekrit'
CONSUMER_SECRET = u'123'
REQUEST_TOKEN_URL = 'https://testpypi.python.org/oauth/request_token'
AUTHORIZATION_URL = 'https://testpypi.python.org/oauth/authorise'
ACCESS_TOKEN_URL = 'https://testpypi.python.org/oauth/access_token'
RESOURCE_URL = 'https://testpypi.python.org/oauth/test'
CALLBACK_URL = 'http://spam.example/back'


def register():
    #### Step 1: Obtain a request token
    # We start asking for a request token, which will finally turn into an
    # access token, the one we need to operate on behalf of the user.
    auth = OAuth1(CONSUMER_KEY, CONSUMER_SECRET, signature_type='auth_header')
    response = requests.get(REQUEST_TOKEN_URL, auth=auth, verify=False)
    qs = parse_qs(response.text)
    REQUEST_TOKEN = unicode(qs['oauth_token'][0])
    REQUEST_SECRET = unicode(qs['oauth_token_secret'][0])


    #### Step 2: Redirect the user for getting authorization
    # In this step we give the user a link or open a web browser redirecting
    # him to an endpoint, passing the REQUEST_TOKEN we got in the previous step
    # as a url parameter. The user will get a dialog asking for authorization
    # for our application. PyPI will redirect the user back to the URL you
    # provide in CALLBACK_URL.
    import webbrowser
    webbrowser.open("%s?oauth_token=%s&oauth_callback=%s" % (AUTHORIZATION_URL,
        REQUEST_TOKEN, CALLBACK_URL))

    raw_input('[press enter when ready]')


    #### Step 3: Authenticate
    # Once we get user's authorization, we request a final access token, to
    # operate on behalf of the user. We build a new hook using previous request
    # token information achieved at step 1. The request token will have been
    # authorized at step 2.
    # This code is typically invoked in the page called at CALLBACK_URL.
    auth = OAuth1(CONSUMER_KEY, CONSUMER_SECRET, REQUEST_TOKEN, REQUEST_SECRET,
        signature_type='auth_header')
    response = requests.get(ACCESS_TOKEN_URL, auth=auth, verify=False)
    response = parse_qs(response.content)
    ACCESS_TOKEN = unicode(response['oauth_token'][0])
    ACCESS_SECRET = unicode(response['oauth_token_secret'][0])
    # The ACCESS_TOKEN and ACCESS_SECRET are the credentials we need to use for
    # handling user's oauth, so most likely you will want to persist them
    # somehow. These are the ones you should use for building a requests
    # session with a new hook. Beware that not all OAuth APIs provide unlimited
    # time credentials.

    print 'ACCESS TOKEN', ACCESS_TOKEN
    print 'ACCESS SECRET', ACCESS_SECRET

    ### Optional Step 4: Access a protected resource
    # Now we have an access token we may access the protected resources on
    # behalf of the user. In this case we access the test URL which will echo
    # back to us the authenticated user and any parameters we pass.
    auth = OAuth1(CONSUMER_KEY, CONSUMER_SECRET, ACCESS_TOKEN, ACCESS_SECRET,
        signature_type='auth_header')
    response = requests.get(RESOURCE_URL, params={'test': 'spam'}, auth=auth,
        verify=False)
    print response.text


def test(ACCESS_TOKEN, ACCESS_SECRET, **params):
    '''Access the test resource passing optional parameters.

    The test resource will echo back the authenticated user and any parameters
    we pass.
    '''
    RESOURCE_URL = 'https://testpypi.python.org/oauth/test'
    auth = OAuth1(CONSUMER_KEY, CONSUMER_SECRET, ACCESS_TOKEN, ACCESS_SECRET,
        signature_type='auth_header')
    client = SimpleOAuthClient(CONSUMER_KEY, CONSUMER_SECRET, access_token)
    response = requests.get(RESOURCE_URL, params=params, auth=auth,
        verify=False)
    return response.text


def flatten_params(params):
    '''Convert a dict to to a list of two-tuples of (k, v) where v is
    potentially each element from a list of values.

    Also ignore empty values as these confuse signature generation.
    '''
    flattened = []
    for k, v in params.items():
        if isinstance(v, list):
            for v in v:
                if v:
                    flattened.append((k, v))
        elif v:
            flattened.append((k, v))
    return [e for e in flattened if e[1]]


def release(ACCESS_TOKEN, ACCESS_SECRET, name, version, summary, **optional):
    '''Register a new package, or release of an existing package.

    The "optional" parameters match fields in PEP 345.

    The complete list of parameters are:

    Single value: description, keywords, home_page, author, author_email,
        maintainer, maintainer_email, license, requires_python

    Multiple values: requires, provides, obsoletes, requires_dist,
        provides_dist, obsoletes_dist, requires_external, project_url,
        classifiers.

    For parameters with multiple values, pass them as lists of strings.

    The API will default metadata_version to '1.2' for you. The other valid
    value is '1.0'.

    Two additional metadata fields are available specific to PyPI:

    1. _pypi_hidden: If set to '1' the relase will be hidden from listings and
       searches.
    2. bugtrack_url: This will be displayed on package pages.
    '''
    RESOURCE_URL = 'https://testpypi.python.org/oauth/add_release'
    auth = OAuth1(CONSUMER_KEY, CONSUMER_SECRET, ACCESS_TOKEN, ACCESS_SECRET,
        signature_type='auth_header')
    params = {u'name': name, u'version': version, u'summary': summary}
    params.update(optional)
    data = flatten_params(params)
    response = requests.post(RESOURCE_URL, data=data, auth=auth,
        verify=False)
    return response.text


def upload(ACCESS_TOKEN, ACCESS_SECRET, name, version, content,
        filename, filetype, **optional):
    '''Upload a file for a package release. If the release does not exist then
    it will be registered automatically.

    The name and version identify the package release to upload the file
    against. The content and filetype are specific to the file being uploaded.

    content - an readable file object
    filetype - one of the standard distutils file types ("sdist", "bdist_win",
        etc.)

    There are several optional parameters:

    pyversion - specify the 'N.N' Python version the distribution works with.
        This is not needed for source distributions but required otherwise.
    comment - use if there's multiple files for one distribution type.
    md5_digest - supply the MD5 digest of the file content to verify
        transmission
    gpg_signature - ASCII armored GPG signature for the file content
    protocol_version - defaults to "1" (currently the only valid value)

    Additionally the release parameters are as specified for release() above.
    '''
    RESOURCE_URL = 'https://testpypi.python.org/oauth/upload'
    auth = OAuth1(CONSUMER_KEY, CONSUMER_SECRET, ACCESS_TOKEN, ACCESS_SECRET,
        signature_type='auth_header')
    params = dict(name=name, version=version, filename=filename,
        filetype=filetype, protocol_version='1')
    params.update(optional)
    data = flatten_params(params)
    files = dict(content=(filename, content))
    response = requests.post(RESOURCE_URL, params=params, files=files,
        auth=auth, verify=False)
    return response.text

# TODO docupload

if __name__ == '__main__':
    #register()

    ACCESS_TOKEN = u'AJLks8p4zezH2ud9R7OQy98eRLXf8zut'
    ACCESS_SECRET = u'vSXBEWk5kn6wvVGivILPyBmtRitDvJq0cVcmBDk57eX2XCENvp2da3ou7v09TxrL'
    name = u'spam'
    version = u'3.3.1'
    summary = u'spam via OAuth'
    classifiers = [u'Topic :: Security', u'Environment :: Console']
    print 'REGISTERING', name, version
    print release(ACCESS_TOKEN, ACCESS_SECRET, name, version, summary,
      classifiers=classifiers)

    name = u'spam'
    version = u'3.3.1'
    filename = u'spam-3.3.1.tar.gz'
    filetype = u'sdist'
    content = open('/Users/richard/src/projects/spam/dist/' + filename, 'rb')
    #print 'UPLOADING', filename
    #print upload(ACCESS_TOKEN, ACCESS_SECRET, name, version, content,
        #filename, filetype)
