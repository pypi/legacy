-- Table structure for table: users
CREATE TABLE users ( 
   name TEXT PRIMARY KEY, 
   password TEXT, 
   email TEXT, 
   public_key TEXT
);
CREATE INDEX users_email_idx ON users(email);


-- Table structure for table: rego_otk
CREATE TABLE rego_otk ( 
   name TEXT REFERENCES users, 
   otk TEXT );
CREATE INDEX rego_otk_name_idx ON rego_otk(name);


-- Table structure for table: journals
CREATE TABLE journals ( 
   name TEXT, 
   version TEXT, 
   action TEXT, 
   submitted_date TIMESTAMP, 
   submitted_by TEXT REFERENCES users, 
   submitted_from TEXT
);
CREATE INDEX journals_name_idx ON journals(name);
CREATE INDEX journals_version_idx ON journals(version);


-- Table structure for table: packages
CREATE TABLE packages ( 
   name TEXT PRIMARY KEY, 
   stable_version TEXT
);


-- Table structure for table: releases
CREATE TABLE releases ( 
   name TEXT REFERENCES packages,
   version TEXT,
   author TEXT,
   author_email TEXT,
   maintainer TEXT,
   maintainer_email TEXT,
   home_page TEXT,
   license TEXT,
   summary TEXT,
   description TEXT,
   description_html TEXT,
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
SELECT setval('trove_ids', 1000) FROM dual;


-- Table structure for table: release_classifiers
CREATE TABLE release_classifiers (
   name TEXT,
   version TEXT,
   trove_id INTEGER REFERENCES trove_classifiers,
   FOREIGN KEY (name, version) REFERENCES releases (name, version)
);
CREATE INDEX rel_class_name_idx ON release_classifiers(name);
CREATE INDEX rel_class_version_id_idx ON release_classifiers(version);
CREATE INDEX rel_class_trove_id_idx ON release_classifiers(trove_id);


-- Table structure for table: release_provides
CREATE TABLE release_provides (
   name TEXT,
   version TEXT,
   specifier TEXT,
   FOREIGN KEY (name, version) REFERENCES releases (name, version)
);
CREATE INDEX rel_prov_name_idx ON release_provides(name);
CREATE INDEX rel_prov_version_id_idx ON release_provides(version);


-- Table structure for table: release_requires
CREATE TABLE release_requires (
   name TEXT,
   version TEXT,
   specifier TEXT,
   FOREIGN KEY (name, version) REFERENCES releases (name, version)
);
CREATE INDEX rel_req_name_idx ON release_requires(name);
CREATE INDEX rel_req_version_id_idx ON release_requires(version);


-- Table structure for table: release_obsoletes
CREATE TABLE release_obsoletes (
   name TEXT,
   version TEXT,
   specifier TEXT,
   FOREIGN KEY (name, version) REFERENCES releases (name, version)
);
CREATE INDEX rel_obs_name_idx ON release_obsoletes(name);
CREATE INDEX rel_obs_version_id_idx ON release_obsoletes(version);


-- Table structure for table: package_files
-- python version is only first two digits
-- actual file path is constructed <py version>/<a-z>/<name>/<filename>
-- we remember filename because it can differ
CREATE TABLE release_files ( 
   name TEXT,
   version TEXT,
   python_version TEXT,
   packagetype TEXT,
   comment_text TEXT,
   filename TEXT UNIQUE,
   md5_digest TEXT UNIQUE,
   FOREIGN KEY (name, version) REFERENCES releases (name, version)
);
CREATE INDEX release_files_name_idx ON release_files(name);
CREATE INDEX release_files_version_idx ON release_files(version);
CREATE INDEX release_files_packagetype_idx ON release_files(packagetype);


-- Table structure for table: package_urls
CREATE TABLE release_urls ( 
   name TEXT,
   version TEXT,
   url TEXT, 
   packagetype TEXT,
   FOREIGN KEY (name, version) REFERENCES releases (name, version)
);
CREATE INDEX release_urls_name_idx ON release_urls(name);
CREATE INDEX release_urls_version_idx ON release_urls(version);
CREATE INDEX release_urls_packagetype_idx ON release_urls(packagetype);


-- Table structure for table: roles
-- Note: roles are Maintainer, Admin, Owner
CREATE TABLE roles ( 
   role_name TEXT, 
   user_name TEXT REFERENCES users, 
   package_name TEXT REFERENCES packages
);
CREATE INDEX roles_pack_name_idx ON roles(package_name);
CREATE INDEX roles_user_name_idx ON roles(user_name);

