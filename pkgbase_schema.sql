-- Table structure for table: journals
create table journals ( 
   name VARCHAR[255], 
   version VARCHAR[255], 
   action TEXT, 
   submitted_date DATETIME, 
   submitted_by VARCHAR[255] REFERENCES users, 
   submitted_from VARCHAR[255]
);

create index journals_name_idx on journals(name);
create index journals_version_idx on journals(version);


-- Table structure for table: packages
create table packages ( 
   name VARCHAR[255] PRIMARY KEY, 
   stable_version VARCHAR[255]
);
create index packages_name_idx on packages(name);


-- Table structure for table: rego_otk
create table rego_otk ( 
   name VARCHAR[255], 
   otk TEXT );
create index rego_otk_name_idx on rego_otk(name);


-- Table structure for table: release_classifiers
create table release_classifiers (
   name VARCHAR[255],
   version VARCHAR[255],
   trove_id INTEGER REFERENCES trove_classifiers,
   FOREIGN KEY (name, version) REFERENCES releases (name, version),
);
create index rel_class_name_idx on release_classifiers(name);
create index rel_class_version_id_idx on release_classifiers(version);
create index rel_class_trove_id_idx on release_classifiers(trove_id);


-- Table structure for table: releases
create table releases ( 
   name VARCHAR[255] FOREIGN KEY REFERENCES packages,
   version VARCHAR[255],
   author TEXT,
   author_email TEXT,
   maintainer TEXT,
   maintainer_email TEXT,
   home_page TEXT,
   license TEXT,
   summary TEXT,
   description TEXT,
   keywords TEXT,
   platform TEXT,
   download_url TEXT,
   _pypi_ordering INTEGER,
   _pypi_hidden BOOLEAN,
   primary key (name, version),
);
create index release_name_idx on releases(name);
create index release_pypi_hidden_idx on releases(_pypi_hidden);
create index release_version_idx on releases(version);


-- Table structure for table: package_files
-- python version is only first two digits
-- actual filename is constructed <py version>/<a-z>/<name>/<distutils filename>
create table package_files ( 
   name VARCHAR[255],
   version VARCHAR[255],
   python_version VARCHAR[255],
   packagetype TEXT,
   UNIQUE (name, version, python_version, packagetype),
   FOREIGN KEY (name, version) REFERENCES releases (name, version),
);
create index release_name_idx on releases(name);
create index release_version_idx on releases(version);
create index package_urls_packagetype_idx on package_urls(packagetype);


-- Table structure for table: package_urls
create table package_urls ( 
   name VARCHAR[255],
   version VARCHAR[255],
   url TEXT, 
   packagetype TEXT,
   FOREIGN KEY (name, version) REFERENCES releases (name, version),
);
create index release_name_idx on releases(name);
create index release_version_idx on releases(version);
create index package_urls_packagetype_idx on package_urls(packagetype);


-- Table structure for table: roles
-- Note: roles are Maintainer, Admin, Owner
create table roles ( 
   role_name VARCHAR[255], 
   user_name VARCHAR[255] REFERENCES users, 
   package_name VARCHAR[255] REFERENCES packages,
);
create index roles_pack_name_idx on roles(package_name);
create index roles_user_name_idx on roles(user_name);


-- Table structure for table: trove_classifiers
create table trove_classifiers ( 
   id INTEGER PRIMARY KEY, 
   classifier TEXT UNIQUE
);
create index trove_class_class_idx on trove_classifiers(classifier);
create index trove_class_id_idx on trove_classifiers(id);


-- Table structure for table: users
create table users ( 
   name VARCHAR[255] PRIMARY KEY, 
   password VARCHAR[255], 
   email TEXT, 
   public_key TEXT
);
create index users_email_idx on users(email);
create index users_name_idx on users(name);

