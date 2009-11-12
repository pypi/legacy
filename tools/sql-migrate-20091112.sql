CREATE TABLE poll(
  name TEXT PRIMARY KEY REFERENCES users,
  vote INTEGER,
  date TIMESTAMP,
  host TEXT
);
GRANT ALL ON poll TO pypi;
