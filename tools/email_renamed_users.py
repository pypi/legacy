import smtplib
import pickle
import sys
import os

from email.mime.text import MIMEText

# Workaround current bug in docutils:
# http://permalink.gmane.org/gmane.text.docutils.devel/6324
import docutils.utils

root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path = [root] + sys.path

import config
import store

config = config.Config("config.ini")
store = store.Store(config)

EMAIL_PLURAL = """
Hello there!

PyPI has begun to enforce restrictions on what a valid Python package name
contains. These rules are:

* Must contain ONLY ASCII letters, digits, underscores, hyphens, and
periods
* Must begin and end with an ASCII letter or digit

You are listed as an owner or maintainer on %(old)s. Due to
the new rules these packages will be renamed to %(new)s.
These new names represent what someone using pip or easy_install would
already have had to use in order to install your packages.

I am sorry for any inconvenience this may have caused you.
"""


EMAIL_SINGLE = """
Hello there!

PyPI has begun to enforce restrictions on what a valid Python package name
contains. These rules are:

* Must contain ONLY ASCII letters, digits, underscores, hyphens, and
periods
* Must begin and end with an ASCII letter or digit

You are listed as an owner or maintainer on %(old)s. Due to
the new rules this package will be renamed to %(new)s.
These new names represent what someone using pip or easy_install would
already have had to use in order to install your package.

I am sorry for any inconvenience this may have caused you.
"""

with open("renamed.pkl") as pkl:
    renamed = pickle.load(pkl)


# Build up a list of all users to email
users = {}
for old, new in renamed:
    for role in store.get_package_roles(new):
        user_packages = users.setdefault(role["user_name"], [])
        user_packages.append((old, new))

# Email each user
server = smtplib.SMTP(config.mailhost)
for username, packages in users.iteritems():

    user = store.get_user(username)

    if not user["email"]:
        continue

    if len(packages) > 1:
        msg = MIMEText(EMAIL_PLURAL % {
                                "old": ", ".join([x[0] for x in packages]),
                                "new": ", ".join([x[1] for x in packages]),
                            })
    elif packages:
        msg = MIMEText(EMAIL_SINGLE % {
                                "old": packages[0][0],
                                "new": packages[0][1],
                            })

    msg["Subject"] = "Important notice about your PyPI packages"
    msg["From"] = "donald@python.org"
    msg["To"] = user["email"]

    server.sendmail("donald@python.org", [user["email"]], msg.as_string())
server.quit()
