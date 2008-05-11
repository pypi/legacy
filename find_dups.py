import sys, os, urllib, StringIO, traceback, cgi, binascii, getopt
import store, config

try:
    config = config.Config(sys.argv[1], 'webui')
except IndexError:
    print "Usage: find_dups.py config.ini"
    raise SystemExit

store = store.Store(config)
store.open()

def owner_email(p):
    result = set()
    for r,u in store.get_package_roles(p):
        if r == 'Owner':
            result.add(store.get_user(u)['email'])
    return result

def mail_dup(email, package1, package2):
    email = "martin@v.loewis.de"
    f = os.popen("/usr/lib/sendmail "+email, "w")
    f.write("To: %s\n" % email)
    f.write("From: martin@v.loewis.de\n")
    f.write("Subject: Please cleanup PyPI package names\n\n")
    f.write("Dear Package Owner,\n")
    f.write("You have currently registered the following to packages,\n")
    f.write("which differ only in case:\n\n%s\n%s\n\n" % (package1, package2))
    f.write("As a recent policy change, we are now rejecting this kind of\n")
    f.write("setup. Please remove one of packages.\n\n")
    f.write("If you need assistance, please let me know.\n\n")
    f.write("Kind regards,\nMartin v. Loewis\n")
    f.close()

lower = {}
for name,version in store.get_packages():
    lname = name.lower()
    if lname in lower:
        owner1 = owner_email(name)
        owner2 = owner_email(lower[lname])
        owners = owner1.intersection(owner2)
        if owners:
            mail_dup(owners.pop(),name,lower[lname])
        else:
            print "Distinct dup", name, lower[lname], owner1, owner2
    lower[lname] = name
