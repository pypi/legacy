CREATE TABLE timestamps (
   name TEXT PRIMARY KEY,
   value TIMESTAMP
);
INSERT INTO timestamps(name, value) VALUES('http','1970-01-01');
INSERT INTO timestamps(name, value) VALUES('ftp','1970-01-01');

ALTER TABLE release_files ADD COLUMN downloads INTEGER;
ALTER TABLE release_files ALTER downloads SET DEFAULT 0;

