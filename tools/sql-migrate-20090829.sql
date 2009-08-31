CREATE TABLE openids (
   id TEXT PRIMARY KEY,
   name TEXT REFERENCES users
);

CREATE TABLE openid_sessions (
   id SERIAL PRIMARY KEY,
   provider TEXT,
   url TEXT,
   assoc_handle TEXT,
   expires TIMESTAMP,
   mac_key TEXT
);

CREATE TABLE openid_stypes (
   id INTEGER REFERENCES openid_sessions ON DELETE CASCADE,
   stype TEXT
);
CREATE INDEX openid_stypes_id ON openid_stypes(id);

CREATE TABLE openid_nonces (
   created TIMESTAMP,
   nonce TEXT
);
CREATE INDEX openid_nonces_created ON openid_nonces(created);
CREATE INDEX openid_nonces_nonce ON openid_nonces(nonce);

CREATE TABLE cookies (
    cookie text PRIMARY KEY,
    name text references users,
    last_seen timestamp
);
CREATE INDEX cookies_last_seen ON cookies(last_seen);
