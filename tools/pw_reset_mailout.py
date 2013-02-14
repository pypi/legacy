import sys
import csv
import time
import smtplib

import store
import config


def main():
    c = config.Config('/data/pypi/config.ini')
    if len(sys.argv) != 2:
        st = store.Store(c)
        st.open()
        w = csv.writer(sys.stdout)
        for user in st.get_users():
            w.writerow((user['name'], user['email']))
    else:
        with open(sys.argv[1]) as f:
            for name, email in csv.reader(f):
                message = TEXT.format(name=name, email=email)
                # send email
                s = smtplib.SMTP()
                s.connect('localhost')
                s.sendmail('richard@python.org', [email], message)
                s.close()
                time.sleep(.1)

TEXT = '''From: richard@python.org
To: {email}
Subject: PyPI security notice


TL;DR: please log into PyPI and change your password.

Dear PyPI user {name},

Recently we have been auditing and improving security of the Python Package
Index (PyPI) and other python.org hosts.

You may be aware that the wiki.python.org host was compromised. Since we must
assume that all passwords stored in that system are also compromised, and we
also assume that some users share passwords between python.org systems, we are
performing a password reset of all PyPI accounts in one week's time, at
2013-02-21 00:00 UTC.

If you log in before that deadline and change your password then you'll be
fine, otherwise you'll need to use the password recovery form after the reset
has occurred.

Additionally, we would ask you to edit your .pypirc files (found in your home
directory) to change the default repository URL to use HTTPS. This may be
achieved by adding a "repository"line to the existing "[pypi]" section in your
file.

[pypi]
repository: https://pypi.python.org/pypi
username: <username>
password: <password>

You should also begin to access PyPI using HTTPS through the web. We're in the
process of installing a new SSL certificate so the current Big Red Certificate
Warning should go away very soon.

These steps are but a couple of those we're intending to take to better secure
PyPI. If you are interested in these matters I encourage you to participate in
the discussion on the catalog SIG:

http://mail.python.org/mailman/listinfo/catalog-sig


    Richard Jones
    richard@python.org
    PyPI Maintainer
'''

if __name__ == '__main__':
    main()
