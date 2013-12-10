-- tables for the oauth library

CREATE TABLE oauth_consumers (
      consumer              varchar(32) primary key,
      secret                varchar(64) not null,
      date_created          date not null,
      created_by TEXT REFERENCES users ON UPDATE CASCADE,
      last_modified         date not null,
      description           varchar(255) not null
);

CREATE TABLE oauth_request_tokens (
      token                 varchar(32) primary key,
      secret                varchar(64) not null,
      consumer              varchar(32) not null,
      callback              text,
      date_created          date not null,
      "user" TEXT REFERENCES users ON UPDATE CASCADE ON DELETE CASCADE
);

CREATE TABLE oauth_access_tokens (
      token                 varchar(32) primary key,
      secret                varchar(64) not null,
      consumer              varchar(32) not null,
      date_created          date not null,
      last_modified         date not null,
      "user" TEXT REFERENCES users ON UPDATE CASCADE ON DELETE CASCADE
);

CREATE TABLE oauth_nonce (
      timestamp             integer not null,
      consumer              varchar(32) not null,
      nonce                 varchar(32) not null,
      token                 varchar(32)
);

