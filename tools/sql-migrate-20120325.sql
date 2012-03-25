begin;
CREATE TABLE oauth_request_tokens2 (
      token                 varchar(32) primary key,
      secret                varchar(64) not null,
      consumer              varchar(32) not null,
      callback              text,
      date_created          date not null,
      user_name TEXT REFERENCES users ON UPDATE CASCADE ON DELETE CASCADE
);

CREATE TABLE oauth_access_tokens2 (
      token                 varchar(32) primary key,
      secret                varchar(64) not null,
      consumer              varchar(32) not null,
      date_created          date not null,
      last_modified         date not null,
      user_name TEXT REFERENCES users ON UPDATE CASCADE ON DELETE CASCADE
);

insert into oauth_request_tokens2(token, secret, consumer, 
              callback, date_created, user_name) 
select token, secret, consumer, callback, date_created, 
    user from oauth_request_tokens;
drop table oauth_request_tokens;
alter table oauth_request_tokens2 rename to oauth_request_tokens;

insert into oauth_access_tokens2(token, secret, consumer, 
     date_created, last_modified, user_name) 
select token, secret, consumer, date_created, last_modified, 
    user from oauth_access_tokens;
drop table oauth_access_tokens;
alter table oauth_access_tokens2 rename to oauth_access_tokens;

end;
