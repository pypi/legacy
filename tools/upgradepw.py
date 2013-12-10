#!/usr/bin/python
import base64
import os
import sys

# Workaround current bug in docutils:
# http://permalink.gmane.org/gmane.text.docutils.devel/6324
import docutils.utils


root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(root)

import config
import store
import passlib.registry

bcrypt = passlib.registry.get_crypt_handler("bcrypt")
bcrypt_sha1 = passlib.registry.get_crypt_handler("bcrypt_sha1")

cfg = config.Config(os.path.join(root, "config.ini"))
st = store.Store(cfg)

print "Migrating passwords to bcrypt_sha1 from unsalted sha1....",

st.open()
for i, u in enumerate(st.get_users()):
    user = st.get_user(u['name'])
    # basic sanity check to allow it to run concurrent with users accessing
    if len(user['password']) == 40 and "$" not in user["password"]:
        # Hash the existing sha1 password with bcrypt
        bcrypted = bcrypt.encrypt(user["password"])

        # Base64 encode the bcrypted password so that it's just a blob of data
        encoded = base64.b64encode(bcrypted)

        st.setpasswd(user['name'], bcrypt_sha1._hash_prefix + encoded,
                hashed=True,
            )

    # Commit every 20 users
    if not i % 20:
        st.commit()
        st.open()

st.commit()
st.close()

print "[ok]"
