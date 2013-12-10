begin;
CREATE TABLE oid_nonces
(
   server_url VARCHAR(2047) NOT NULL,
   timestamp INTEGER NOT NULL,
   salt CHAR(40) NOT NULL,
   PRIMARY KEY (server_url, timestamp, salt)
);

CREATE TABLE oid_associations
(
   server_url VARCHAR(2047) NOT NULL,
   handle VARCHAR(255) NOT NULL,
   secret BYTEA NOT NULL,
   issued INTEGER NOT NULL,
   lifetime INTEGER NOT NULL,
   assoc_type VARCHAR(64) NOT NULL,
   PRIMARY KEY (server_url, handle),
   CONSTRAINT secret_length_constraint CHECK (LENGTH(secret) <= 128)
);

GRANT ALL ON oid_nonces, oid_associations TO pypi;
commit;
