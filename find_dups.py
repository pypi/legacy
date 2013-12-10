import sys, os, urllib, StringIO, traceback, cgi, binascii, getopt
import store, config

try:
    config = config.Config(sys.argv[1])
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

def mail_distinct_dup(users, package1, package2):
    f = os.popen("/usr/lib/sendmail "+" ".join(users), "w")
    for email in users:
        f.write("To: %s\n" % email)
    f.write("From: martin@v.loewis.de\n")
    f.write("Subject: Please cleanup PyPI package names\n\n")
    f.write("Dear Package Owners,\n")
    f.write("You have currently registered the following to packages,\n")
    f.write("which differ only in case:\n\n%s\n%s\n\n" % (package1, package2))
    f.write("As a recent policy change, we are now rejecting this kind of\n")
    f.write("setup. Please remove one of packages.\n\n")
    f.write("If you need assistance, please let me know.\n\n")
    f.write("Kind regards,\nMartin v. Loewis\n")
    f.close()

def dup_packages():
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
                mail_distinct_dup(owner1.union(owner2),name,lower[lname])
        lower[lname] = name

def mail_unused_user(email, all, unused):
    #for user in unused:
    #    if all-unused:
    #        newuser = (all-unused).pop()
    #        print "UPDATE journals SET submitted_by='%s' WHERE submitted_by='%s';" % (newuser,user)
    #    print "DELETE FROM rego_otk WHERE name='%s';" % user
    #    print "DELETE FROM users WHERE name='%s';" % user
    email = "martin@v.loewis.de"
    f = os.popen("/usr/lib/sendmail "+email, "w")
    f.write("To: %s\n" % email)
    f.write("From: martin@v.loewis.de\n")
    f.write("Subject: Unused PyPI account deleted\n\n")
    f.write("Dear PyPI user,\n")
    f.write("You have currently registered the following user names,\n")
    f.write("all for the email account %s: \n\n%s\n\n" % (email, ' '.join(all)))
    f.write("As this kind of setup causes problems, we would like to delete,\n")
    f.write("one of the accounts, or somehow merge it with the other.\n")
    f.write("Please let me know what kind of action I should take,\n")
    f.write("please respond before February 1st.\n\n")
    f.write("Kind regards,\nMartin v. Loewis\n")
    f.close()

def dup_users():
    by_email = {}
    for user in store.get_users():
        email = user['email']
        by_email[email] = by_email.get(email, []) + [user['name']]
    rest = []
    print "BEGIN;"
    for email, users in by_email.items():
        if len(users) == 1: continue
        users = set(users)
        unused = set()
        for user in users:
            if not store.user_packages(user):
                unused.add(user)
        if 1:#len(users-unused)<=1:
            mail_unused_user(email, users, unused)
        else:
            rest.append((email, users, unused))
    print "COMMIT;"
    for r in rest:
        print r

dup_users()
