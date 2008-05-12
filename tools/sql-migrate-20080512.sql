ALTER TABLE packages ADD COLUMN normalized_name TEXT;
\echo Run store.py update_normalized_text now
ALTER TABLE users ADD COLUMN last_login TIMESTAMP;
