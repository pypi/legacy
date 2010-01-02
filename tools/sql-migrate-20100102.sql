CREATE TABLE sshkeys(
   id SERIAL PRIMARY KEY,
   name TEXT REFERENCES users ON DELETE CASCADE,
   key TEXT
);
CREATE INDEX sshkeys_name ON sshkeys(name);
GRANT ALL ON sshkeys TO pypi;
GRANT ALL ON sshkeys_id_seq TO pypi;
