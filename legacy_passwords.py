import base64
import hashlib

import passlib.exc as exc
import passlib.utils.handlers as uh

from passlib.registry import get_crypt_handler
from passlib.utils import to_unicode
from passlib.utils.compat import uascii_to_str


passlib_bcrypt = get_crypt_handler("bcrypt")


class bcrypt_sha1(uh.StaticHandler):

    name = "bcrypt_sha1"
    _hash_prefix = u"$bcrypt_sha1$"

    def _calc_checksum(self, secret):
        # Hash the secret with sha1 first
        secret = hashlib.sha1(secret).hexdigest()

        # Hash it with bcrypt
        return passlib_bcrypt.encrypt(secret)

    def to_string(self):
        assert self.checksum is not None
        return uascii_to_str(self._hash_prefix + base64.b64encode(self.checksum))

    @classmethod
    def from_string(cls, hash, **context):
        # default from_string() which strips optional prefix,
        # and passes rest unchanged as checksum value.
        hash = to_unicode(hash, "ascii", "hash")
        hash = cls._norm_hash(hash)
        # could enable this for extra strictness
        ##pat = cls._hash_regex
        ##if pat and pat.match(hash) is None:
        ##    raise ValueError("not a valid %s hash" % (cls.name,))
        prefix = cls._hash_prefix
        if prefix:
            if hash.startswith(prefix):
                hash = hash[len(prefix):]
            else:
                raise exc.InvalidHashError(cls)

        # Decode the base64 stored actual hash
        hash = unicode(base64.b64decode(hash))

        return cls(checksum=hash, **context)

    @classmethod
    def verify(cls, secret, hash, **context):
        # NOTE: classes with multiple checksum encodings should either
        # override this method, or ensure that from_string() / _norm_checksum()
        # ensures .checksum always uses a single canonical representation.
        uh.validate_secret(secret)
        self = cls.from_string(hash, **context)
        chk = self.checksum
        if chk is None:
            raise exc.MissingDigestError(cls)

        # Actually use the verify from passlib_bcrypt after hashing the secret
        #   with sha1
        secret = hashlib.sha1(secret).hexdigest()
        return passlib_bcrypt.verify(secret, chk)
