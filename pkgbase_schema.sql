-- Table structure for table: users
CREATE TABLE users ( 
   name VARCHAR[255] PRIMARY KEY, 
   password VARCHAR[255], 
   email TEXT, 
   public_key TEXT
);
CREATE INDEX users_email_idx ON users(email);


-- Table structure for table: rego_otk
CREATE TABLE rego_otk ( 
   name VARCHAR[255] REFERENCES users, 
   otk TEXT );
CREATE INDEX rego_otk_name_idx ON rego_otk(name);


-- Table structure for table: journals
CREATE TABLE journals ( 
   name VARCHAR[255], 
   version VARCHAR[255], 
   action TEXT, 
   submitted_date TIMESTAMP, 
   submitted_by VARCHAR[255] REFERENCES users, 
   submitted_from VARCHAR[255]
);
CREATE INDEX journals_name_idx ON journals(name);
CREATE INDEX journals_version_idx ON journals(version);


-- Table structure for table: packages
CREATE TABLE packages ( 
   name VARCHAR[255] PRIMARY KEY, 
   stable_version VARCHAR[255]
);


-- Table structure for table: releases
CREATE TABLE releases ( 
   name VARCHAR[255] REFERENCES packages,
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
   PRIMARY KEY (name, version)
);
CREATE INDEX release_pypi_hidden_idx ON releases(_pypi_hidden);


-- Table structure for table: trove_classifiers
CREATE TABLE trove_classifiers ( 
   id INTEGER PRIMARY KEY, 
   classifier TEXT UNIQUE
);
CREATE INDEX trove_class_class_idx ON trove_classifiers(classifier);
CREATE INDEX trove_class_id_idx ON trove_classifiers(id);


-- trove ids sequence
CREATE TABLE dual (dummy INTEGER);
INSERT INTO dual VALUES (1);
CREATE SEQUENCE trove_ids;
SELECT setval('trove_ids', 1000) FROM dual


-- Table structure for table: release_classifiers
CREATE TABLE release_classifiers (
   name VARCHAR[255],
   version VARCHAR[255],
   trove_id INTEGER REFERENCES trove_classifiers,
   FOREIGN KEY (name, version) REFERENCES releases (name, version)
);
CREATE INDEX rel_class_name_idx ON release_classifiers(name);
CREATE INDEX rel_class_version_id_idx ON release_classifiers(version);
CREATE INDEX rel_class_trove_id_idx ON release_classifiers(trove_id);


-- Table structure for table: package_files
-- python version is only first two digits
-- actual filename is constructed <py version>/<a-z>/<name>/<distutils filename>
CREATE TABLE package_files ( 
   name VARCHAR[255],
   version VARCHAR[255],
   python_version VARCHAR[255],
   packagetype TEXT,
   UNIQUE (name, version, python_version, packagetype),
   FOREIGN KEY (name, version) REFERENCES releases (name, version)
);
CREATE INDEX release_name_idx ON releases(name);
CREATE INDEX release_version_idx ON releases(version);
CREATE INDEX package_files_packagetype_idx ON package_files(packagetype);


-- Table structure for table: package_urls
CREATE TABLE package_urls ( 
   name VARCHAR[255],
   version VARCHAR[255],
   url TEXT, 
   packagetype TEXT,
   FOREIGN KEY (name, version) REFERENCES releases (name, version)
);
CREATE INDEX release_name_idx ON releases(name);
CREATE INDEX release_version_idx ON releases(version);
CREATE INDEX package_urls_packagetype_idx ON package_urls(packagetype);


-- Table structure for table: roles
-- Note: roles are Maintainer, Admin, Owner
CREATE TABLE roles ( 
   role_name VARCHAR[255], 
   user_name VARCHAR[255] REFERENCES users, 
   package_name VARCHAR[255] REFERENCES packages
);
CREATE INDEX roles_pack_name_idx ON roles(package_name);
CREATE INDEX roles_user_name_idx ON roles(user_name);


