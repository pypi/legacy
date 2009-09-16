CREATE TABLE ratings(
   name TEXT,
   version TEXT,
   user_name TEXT REFERENCES users ON DELETE CASCADE,
   date TIMESTAMP,
   rating INTEGER,
   message TEXT,
   PRIMARY KEY (name, version, user_name),
   FOREIGN KEY (name, version) REFERENCES releases ON UPDATE CASCADE ON DELETE CASCADE
);
CREATE INDEX rating_name_version ON ratings(name, version);
GRANT ALL ON ratings TO pypi;