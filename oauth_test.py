'''Simplified interface to OAuth as a client.

DOES OAuth 1.0 and 1.0a (oauth_verifier is ignored)

'''
import urllib
import urlparse
import httplib
import oauth

class OAuthError(Exception):
    def __str__(self):
        if len(self.args) > 1:
            message, response = self.args
            return '%s (%s: %s)\n%s'%(message, response.status,
                response.reason, response.read())
        else:
            return self.args[0]

class SimpleOAuthClient(oauth.OAuthClient):
    '''Encapsulate a connection to an OAuth server.
    '''

    def __init__(self, key, secret, token=None):
        consumer = oauth.OAuthConsumer(key, secret)
        super(SimpleOAuthClient, self).__init__(consumer, token)

    def _attempt_access(self, url, oauth_request, data=None):
        if data:
            data = urllib.urlencode(data)

        # connect to the remote end
        scheme, host = urlparse.urlparse(url)[:2]
        if scheme == 'https':
            connection = httplib.HTTPSConnection(host)
        else:
            connection = httplib.HTTPConnection(host)

        if data:
            kw = dict(headers=oauth_request.to_header())
            if oauth_request.http_method == 'GET' and data:
                url += '?' + data
            elif oauth_request.http_method == 'POST':
                kw['headers']['Content-Type'] = 'application/x-www-form-urlencoded'
                kw['body'] = data
            connection.request(oauth_request.http_method, url, **kw)
        else:
            connection.request(oauth_request.http_method, url,
                headers=oauth_request.to_header())

        # parse the token from the response
        response = connection.getresponse()
        if response.status != 200:
            raise OAuthError('%s failed: %s %s'%(url, response.status,
                response.reason), response)

        return response

    def fetch_request_token(self, url):
        # construct the request for a request token
        signature_method = oauth.OAuthSignatureMethod_HMAC_SHA1()
        oauth_request = oauth.OAuthRequest.from_consumer_and_token(self.consumer,
            http_url=url)
        oauth_request.sign_request(signature_method, self.consumer, None)
        response = self._attempt_access(url, oauth_request)
        return oauth.OAuthToken.from_string(response.read())

    def authorize_url(self, url, callback):
        # ask for the authorizaation URL
        oauth_request = oauth.OAuthRequest.from_token_and_callback(
            token=self.token, callback=callback, http_url=url)

        # invoke the remote end
        host = urlparse.urlparse(url)[1]
        return oauth_request.to_url()

    def fetch_access_token(self, url):
        oauth_request = oauth.OAuthRequest.from_consumer_and_token(
            self.consumer, token=self.token, http_url=url)
        signature_method = oauth.OAuthSignatureMethod_HMAC_SHA1()
        oauth_request.sign_request(signature_method, self.consumer, self.token)
        response = self._attempt_access(url, oauth_request)
        return oauth.OAuthToken.from_string(response.read())

    def access_resource(self, url, parameters, http_method='GET'):
        oauth_request = oauth.OAuthRequest.from_consumer_and_token(
            self.consumer, token=self.token, http_method=http_method,
            http_url=url, parameters=parameters)
        signature_method = oauth.OAuthSignatureMethod_HMAC_SHA1()
        oauth_request.sign_request(signature_method, self.consumer, self.token)
        response = self._attempt_access(url, oauth_request, data=parameters)
        return response.read()

def example_init():
    # test config
    CONSUMER_KEY = 'sekrit'
    CONSUMER_SECRET = '123'
    REQUEST_TOKEN_URL = 'https://testpypi.python.org/oauth/request_token'
    ACCESS_TOKEN_URL = 'https://testpypi.python.org/oauth/access_token'
    AUTHORIZATION_URL = 'https://testpypi.python.org/oauth/authorise'
    RESOURCE_URL = 'https://testpypi.python.org/oauth/test'
    CALLBACK_URL = 'http://spam.example/back'

    def pause():
        raw_input('[press enter when ready]')

    # setup
    print '** OAuth Python Library Example **'
    client = SimpleOAuthClient(CONSUMER_KEY, CONSUMER_SECRET)

    # get request token
    print '* Obtain a request token ...'
    token = client.fetch_request_token(REQUEST_TOKEN_URL)
    print 'key: %s' % str(token.key)
    print 'secret: %s' % str(token.secret)
    pause()

    print '* Authorize the request token ...'
    print '  You need to open the URL printed below in a browser'
    client = SimpleOAuthClient(CONSUMER_KEY, CONSUMER_SECRET, token)
    # this will actually occur only on some callback
    response = client.authorize_url(AUTHORIZATION_URL, CALLBACK_URL)
    print response
    print '... once you have opened the URL and authorised acces you may continue'
    pause()

    # get access token
    print '* Obtain an access token ...'
    pause()
    client.token = token
    token = client.fetch_access_token(ACCESS_TOKEN_URL)
    print 'key: %s' % str(token.key)
    print 'secret: %s' % str(token.secret)
    pause()

def example_access():
    # test config
    CONSUMER_KEY = 'sekrit'
    CONSUMER_SECRET = '123'
    RESOURCE_URL = 'https://testpypi.python.org/oauth/test'

    ACCESS_KEY = 'AJLks8p4zezH2ud9R7OQy98eRLXf8zut'
    ACCESS_SECRET = 'vSXBEWk5kn6wvVGivILPyBmtRitDvJq0cVcmBDk57eX2XCENvp2da3ou7v09TxrL'
    access_token = oauth.OAuthToken(ACCESS_KEY, ACCESS_SECRET)

    # access some protected resources
    print '* Access protected resources ...'
    client = SimpleOAuthClient(CONSUMER_KEY, CONSUMER_SECRET, access_token)
    params = client.access_resource(RESOURCE_URL, {'param_one': 'test'})
    print 'non-oauth parameters: %s' % params


if __name__ == '__main__':
    # for testing you will want to run example_init() and work through that
    # until you get an access token. Then replace ACCESS_KEY and ACCESS_SECRET
    # in example_access() with the key and secret you were assigned.
    #example_init()
    example_access()

