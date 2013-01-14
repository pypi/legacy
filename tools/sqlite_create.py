# HISTORICAL USE ONLY

# IS THE CODE THAT USED TO CONSTRUCT THE SQLITE DATABASE

# IS NOT COMPLETE

# HISTORICAL USE ONLY
cursor.execute('''
    create table ids (
        name varchar,
        num varchar
    )''')
cursor.execute('''
    create table packages (
        name varchar,
        stable_version varchar
    )''')
cursor.execute('''
    create table releases (
        name varchar,
        version varchar,
        author varchar,
        author_email varchar,
        maintainer varchar,
        maintainer_email varchar,
        home_page varchar,
        license varchar,
        summary varchar,
        description varchar,
        keywords varchar,
        platform varchar,
        download_url varchar,
        _pypi_ordering varchar,
        _pypi_hidden varchar
    )''')
cursor.execute('''
    create table trove_classifiers (
        id varchar,
        classifier varchar
    )''')
cursor.execute('''
    create table release_classifiers (
        name varchar,
        version varchar,
        trove_id varchar
    )''')
cursor.execute('''
    create table journals (
        id integer primary key autoincrement,
        name varchar,
        version varchar,
        action varchar,
        submitted_date varchar,
        submitted_by varchar,
        submitted_from varchar
    )''')
cursor.execute('''
    create table users (
        name varchar,
        password varchar,
        email varchar,
        public_key varchar
    )''')
cursor.execute('''
    create table rego_otk (
        name varchar,
        otk varchar
    )''')
cursor.execute('''
    create table roles (
        role_name varchar,
        user_name varchar,
        package_name varchar
    )''')

# init the id counter
cursor.execute('''insert into ids (name, num) values
    ('trove_classifier', 1)''')

# indexes
SQLs = [
"create index ids_name_idx on ids(name)",
"create index journals_name_idx on journals(name)",
"create index journals_version_idx on journals(version)",
"create index packages_name_idx on packages(name)",
"create index rego_otk_name_idx on rego_otk(name)",
"create index rel_class_name_idx on release_classifiers(name)",
"create index rel_class_trove_id_idx on "
    "release_classifiers(trove_id)",
"create index rel_class_version_id_idx on "
    "release_classifiers(version)",
"create index release_name_idx on releases(name)",
"create index release_pypi_hidden_idx on releases(_pypi_hidden)",
"create index release_version_idx on releases(version)",
"create index roles_pack_name_idx on roles(package_name)",
"create index roles_user_name_idx on roles(user_name)",
"create index trove_class_class_idx on "
    "trove_classifiers(classifier)",
"create index trove_class_id_idx on trove_classifiers(id)",
"create index users_email_idx on users(email)",
"create index users_name_idx on users(name)",
]
for sql in SQLs:
    cursor.execute(sql)

# admin user
adminpw = ''.join([random.choice(chars) for x in range(10)])
adminpw = sha.sha(adminpw).hexdigest()
cursor.execute('''
    insert into users (name, password, email) values
    ('admin', '%s', NULL)
    '''%adminpw)
cursor.execute('''
    insert into roles (user_name, role_name, package_name) values
    ('admin', 'Admin', NULL)
    ''')
