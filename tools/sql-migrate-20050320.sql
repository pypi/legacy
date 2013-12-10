
DROP TABLE package_files;

DROP TABLE package_urls;

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


ALTER TABLE users DROP COLUMN public_key;

ALTER TABLE USERS ADD COLUMN gpg_keyid TEXT;

