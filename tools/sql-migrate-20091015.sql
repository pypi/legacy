BEGIN;

ALTER TABLE ratings ADD id SERIAL UNIQUE;
GRANT ALL ON ratings_id_seq TO pypi;

CREATE TABLE comments(
  id SERIAL PRIMARY KEY,
  rating INTEGER REFERENCES ratings(id) ON DELETE CASCADE,
  user_name TEXT REFERENCES users ON DELETE CASCADE,
  date TIMESTAMP,
  message TEXT,
  in_reply_to INTEGER REFERENCES comments ON DELETE CASCADE
);
GRANT ALL ON comments TO pypi;
GRANT ALL ON comments_id_seq TO pypi;

INSERT INTO comments(rating, user_name, date, message) 
  SELECT id, user_name, date, message FROM ratings WHERE message!='';

ALTER TABLE ratings DROP COLUMN message;

CREATE TABLE comments_journal(
  name text,
  version text,
  id INTEGER,
  submitted_by TEXT REFERENCES users ON DELETE CASCADE,
  date TIMESTAMP,
  action TEXT,
  FOREIGN KEY (name, version) REFERENCES releases (name, version) ON DELETE CASCADE
);
GRANT ALL ON comments_journal TO pypi;

END;
