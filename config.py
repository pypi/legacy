import ConfigParser
from urlparse import urlsplit, urlunsplit

from passlib.context import CryptContext
from passlib.registry import register_crypt_handler_path


# Register our legacy password handler
register_crypt_handler_path("bcrypt_sha1", "legacy_passwords")


class Config:
    ''' Read in the config and set up the vars with the correct type.
    '''
    def __init__(self, configfile):
        c = ConfigParser.ConfigParser()
        c.read(configfile)
        self.database_name = c.get('database', 'name')
        self.database_user = c.get('database', 'user')
        if c.has_option('database', 'driver'):
            self.database_driver = c.get('database', 'driver')
        else:
            self.database_driver = 'psycopg2'
        if c.has_option('database', 'password'):
            self.database_pw = c.get('database', 'password')
        else:
            self.database_pw = None
        if c.has_option('database', 'host'):
            self.database_host = c.get('database', 'host')
        else:
            self.database_host = None
        if c.has_option('database', 'port'):
            self.database_port = c.getint('database', 'port')
        else:
            self.database_port = None

        if c.has_option("database", "aws_access_key_id"):
            self.database_aws_access_key_id = c.get("database", "aws_access_key_id")
        else:
            self.database_aws_access_key_id = None

        if c.has_option("database", "aws_secret_access_key"):
            self.database_aws_secret_access_key = c.get("database", "aws_secret_access_key")
        else:
            self.database_aws_secret_access_key = None

        if c.has_option("database", "files_bucket"):
            self.database_files_bucket = c.get("database", "files_bucket")
        else:
            self.database_files_bucket = None

        if c.has_option("database", "docs_bucket"):
            self.database_docs_bucket = c.get("database", "docs_bucket")
        else:
            self.database_docs_bucket = None

        if c.has_option("database", "releases_index_url"):
            self.database_releases_index_url = c.get("database", "releases_index_url")
        else:
            self.database_releases_index_url = None

        if c.has_option("database", "releases_index_name"):
            self.database_releases_index_name = c.get("database", "releases_index_name")
        else:
            self.database_releases_index_name = None

        self.database_files_dir = c.get('database', 'files_dir')
        self.database_docs_dir = c.get('database', 'docs_dir')
        if c.has_option('database', 'pubsubhubbub'):
            self.pubsubhubbub = c.get('database', 'pubsubhubbub')
        else:
            self.pubsubhubbub = None
        if c.has_option('webui', 'package_docs_url'):
            self.package_docs_url = c.get('webui', 'package_docs_url')
        else:
            self.package_docs_url = 'http://pythonhosted.org'
        self.adminemail = c.get('webui', 'adminemail')
        self.replyto = c.get('webui', 'replyto')
        self.url = c.get('webui', 'url')
        self.scheme_host = urlunsplit(urlsplit(self.url)[:2]+('','',''))
        if c.has_option('webui', 'statuspage_id'):
          self.statuspage_id = c.get('webui', 'statuspage_id')
        else:
          self.statuspage_id = False
        self.orig_pydotorg = self.pydotorg = c.get('webui', 'pydotorg')
        if self.url.startswith("https:"):
            self.pydotorg = '/'
        self.simple_script = c.get('webui', 'simple_script')
        self.files_url = c.get('webui', 'files_url')
        self.rss_file = c.get('webui', 'rss_file')
        self.packages_rss_file = c.get('webui', 'packages_rss_file')
        self.debug_mode = c.get('webui', 'debug_mode')
        self.cheesecake_password = c.get('webui', 'cheesecake_password')
        self.key_dir = c.get('webui', 'key_dir')
        self.simple_sign_script = c.get('webui', 'simple_sign_script')
        self.raw_package_prefix = c.get("webui", "raw_package_prefix")
        if c.has_option('webui', 'sshkeys_update'):
            self.sshkeys_update = c.get('webui', 'sshkeys_update')
        else:
            self.sshkeys_update = None
        self.reset_secret = c.get('webui', 'reset_secret')

        self.logfile = c.get('logging', 'file')
        self.mail_logger = c.get('logging', 'mail_logger')
        self.fromaddr = c.get('logging', 'fromaddr')
        self.toaddrs = c.get('logging', 'toaddrs').split(',')

        self.queue_redis_url = c.get('database', 'queue_redis_url')
        self.count_redis_url = c.get('database', 'count_redis_url')
        if c.has_option('database', 'cache_redis_url'):
            self.cache_redis_url = c.get('database', 'cache_redis_url')
        else:
            self.cache_redis_url = None
        if c.has_option('database', 'block_redis_url'):
            self.block_redis_url = c.get('database', 'block_redis_url')
        else:
            self.block_redis_url = None

        if c.has_option('database', 'xmlrpc_redis_url'):
            self.xmlrpc_redis_url = c.get('database', 'xmlrpc_redis_url')
        else:
            self.xmlrpc_redis_url = None

        self.sentry_dsn = c.get('sentry', 'dsn')

        self.passlib = CryptContext(
                # Unless we've manually specified a list of deprecated
                #   algorithms assume we will deprecate all but the default.
                deprecated=["auto"],
                truncate_error=True,
            )

        # Configure a passlib context from the config file
        self.passlib.load_path(configfile, update=True)

        # Get the fastly API key
        self.fastly_api_domain = c.get("fastly", "api_domain")
        self.fastly_api_key = c.get("fastly", "api_key")
        self.fastly_service_id = c.get("fastly", "service_id")

        # Get the smtp configuration
        self.smtp_hostname = c.get("smtp", "hostname")
        self.smtp_auth = c.getboolean("smtp", "auth")
        self.smtp_starttls = c.getboolean("smtp", "starttls")
        if self.smtp_auth:
            self.smtp_login = c.get("smtp", "login")
            self.smtp_password = c.get("smtp", "password")

        self.blocked_timeout = c.get("blocking", "blocked_timeout")
        self.blocked_attempts_user = c.get("blocking", "blocked_attempts_user")
        self.blocked_attempts_ip = c.get("blocking", "blocked_attempts_ip")

        if c.has_option("xmlrpc", "max_concurrent"):
            self.xmlrpc_concurrent_requests = c.getint("xmlrpc", "max_concurrent")
        else:
            self.xmlrpc_concurrent_requests = 9999

        if c.has_option("xmlrpc", "enforce"):
            self.xmlrpc_enforce = c.getboolean("xmlrpc", "enforce")
        else:
            self.xmlrpc_enforce = False

        if c.has_option("xmlrpc", "request_log_file"):
            self.xmlrpc_request_log_file = c.get("xmlrpc", "request_log_file")
        else:
            self.xmlrpc_request_log_file = None

        # Get Authomatic Secret
        self.authomatic_secure = c.get("authomatic", "secure")
        self.authomatic_secret = c.get("authomatic", "secret")

        # Get Google OAuth2 Creds
        self.google_consumer_id = c.get("google", "client_id")
        self.google_consumer_secret = c.get("google", "client_secret")


    def make_https(self):
        if self.url.startswith("http:"):
            self.url = "https"+self.url[4:]
            self.pydotorg = '/'
            self.files_url = "https"+self.files_url[4:]
            self.scheme_host = urlunsplit(urlsplit(self.url)[:2]+('','',''))

    def make_http(self):
        if self.url.startswith("https:"):
            self.url = "http"+self.url[5:]
            self.pydotorg = self.orig_pydotorg
            self.files_url = "http"+self.files_url[5:]
            self.scheme_host = urlunsplit(urlsplit(self.url)[:2]+('','',''))
