CREATE TABLE description_urls (
   name TEXT,
   version TEXT,
   url TEXT,
   FOREIGN KEY (name, version) REFERENCES releases (name, version)
);
CREATE INDEX description_urls_name_idx ON description_urls(name);
CREATE INDEX description_urls_name_version_idx ON description_urls(name, version);
grant all on description_urls to pypi;

-- run 'store.py config.ini updateurls' after installing this change
