-- tables for the oauth library

CREATE TABLE oauth_consumers (
      consumer              varchar2(32) primary key,
      secret                varchar2(64) not null,
      date_created          date not null,
      created_by TEXT REFERENCES users ON UPDATE CASCADE,
      last_modified         date not null,
      description           varchar2(255) not null
);

CREATE TABLE oauth_request_tokens (
      token                 varchar2(32) primary key,
      secret                varchar2(64) not null,
      consumer              varchar2(32) not null,
      date_created          date not null,
      user TEXT REFERENCES users ON UPDATE CASCADE ON DELETE CASCADE
);

CREATE TABLE oauth_access_tokens (
      token                 varchar2(32) primary key,
      secret                varchar2(64) not null,
      consumer              varchar2(32) not null,
      date_created          date not null,
      last_modified         date not null,
      user TEXT REFERENCES users ON UPDATE CASCADE ON DELETE CASCADE
);

CREATE TABLE oauth_nonce (
      date_created          date not null,
      nonce                 varchar2(32) not null,
      token                 varchar2(32) not null,
      UNIQUE(date_created, nonce, token)
);

