"""
Process hosting_mode_migration.json taken from
https://github.com/dstufft/pypi.linkcheck
"""
import smtplib
import pickle
import sys
import os
import json
import traceback

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


EMAIL_BODY = """
Hello,

As part of an ongoing attempt to improve the speed and reliability of PyPI
a change has been made to allow package authors to have more control over
their own packages.

This change allows you as an Owner or Maintainer of "%(project)s" to pick
from 3 different hosting modes for your package, as well as control which
urls are exposed as installable targets for pip, easy_install, and zc.buildout.

You may find these options by going to https://pypi.python.org/, navigating to
your package, and clicking on the "urls" option.

A brief explanation of the 3 hosting mode choices:

#1 - Do not extract URLs from the long description field - only use URLs
     explicitly specified in PyPI and files uploaded to PyPI

     This is the best option to pick, it means that only files you upload to
     PyPI and files that you have explicitly added via the urls page will
     be available for installers to install from.

#2 - Present URLs extracted from the long description field.

    This option introduces a little more noise to your simple index, it will
    present your homepage and download_url from your setup.py as an installable
    target and it will also present any url it finds in your long_description
    as an installable target.

#3 - As above but also ask tools to scrape Homepage and Download URL

    This is the legacy behavior. PyPI will present your homepage and
    download_url as installation targets as well as any url it finds in your
    long_description. On top of that it presents your homepage and download_url
    as crawling targets for the installation tools. Meaning that when looking
    for versions to install pip, easy_install, and zc.buildout will visit each
    of those urls, download the HTML, and process it looking for more tarballs
    to install.

    This option is highly discouraged because it leads to very slow and very
    fragile builds. However all existing packages are currently set to this
    mode because of legacy concerns.


In all hosting modes files uploaded directly to PyPI are available for the
tools to install from.

I've scanned your project "%(project)s" and have determined that it can be
moved from #3 to #1 automatically without affecting the ability to install any
versions. In accordance with PEP438[1] this package will be automatically
migrated to #1 in one month. However if you wish to speed up installs for your
users prior to that I encourage you to manually go and modify your hosting
mode, as well as remove any urls from the list that you do not want people to
attempt to install.

For more information, and detailed instructions on how to do that please
visit http://pypi-externals.caremad.io/help/what/.

[1] http://www.python.org/dev/peps/pep-0438/
"""


filename = os.path.join(
                    os.path.dirname(__file__), "hosting_mode_migration.json")
migrations = json.load(open(filename))
package_users = {}

for package in migrations["pypi-explicit"]:
    # Get all the users for this package
    users = [r["user_name"] for r in store.get_package_roles(package)]
    package_users[package] = users


sent = []

# Email each user
server = smtplib.SMTP(config.mailhost)
for i, (package, users) in enumerate(package_users.iteritems()):
    fpackage = store.find_package(package)

    if not fpackage:
        continue

    package = fpackage[0]
    hosting_mode = store.get_package_hosting_mode(package)

    if hosting_mode != "pypi-scrape-crawl":
        continue

    users = sorted(set(users))

    emails = []
    for username in users:
        user = store.get_user(username)
        if user["email"]:
            emails.append(user["email"])

    msg = MIMEText(EMAIL_BODY % {"project": package})
    msg["Subject"] = "Important Information about %s on PyPI" % package
    msg["From"] = "donald@python.org"
    msg["To"] = ", ".join(emails)

    print "Sending for", package, "[%s/%s]" % (i, len(package_users))

    try:
        server.sendmail("donald@python.org", emails, msg.as_string())
        sent.append(("donald@python.org", emails, msg.as_string()))
    except:
        traceback.print_exc()

server.quit()


with open("mode.sent.pkl", "w") as pkl:
   pickle.dump(sent, pkl)
