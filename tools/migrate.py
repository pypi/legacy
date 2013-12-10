# migrate a historical SQLITE database to a postgres one

import sqlite
import psycopg

old = sqlite.connect(db='pkgbase.db')
cursor = old.cursor()
e = cursor.execute

new = psycopg.connect(database='pypi')
new_cursor = new.cursor()
f = new_cursor.execute

t = [
 'users name password email public_key',
 'packages name stable_version',
 'releases name version author author_email maintainer maintainer_email home_page license summary description keywords platform download_url _pypi_ordering _pypi_hidden',
 'trove_classifiers id classifier',
 'release_classifiers name version trove_id',
 'journals name version action submitted_date submitted_by submitted_from',
 'rego_otk name otk',
 'roles role_name user_name package_name',
]
for table in t:
    l = table.split()
    tn = l[0]
    print tn
    cols = ', '.join(l[1:])
    args = ', '.join(['%s']*(len(l)-1))
    e('select %(cols)s from %(tn)s'%locals())
    for row in cursor.fetchall():
        d = list(row)
        if '_pypi_ordering' in l[1:]: d[-2] = d[-2] and int(float(d[-2]))
        f('insert into %(tn)s (%(cols)s) values (%(args)s)'%locals(),
            tuple(d))

new.commit()
