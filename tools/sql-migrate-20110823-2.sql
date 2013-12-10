create table csrf_tokens (
  name    text REFERENCES users(name) ON DELETE CASCADE,
  token   text,
  end_date timestamp without time zone,
  PRIMARY KEY(name)
);

