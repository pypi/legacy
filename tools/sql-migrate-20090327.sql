-- Table structure for table: mirrors
CREATE TABLE mirrors (
   root_url TEXT PRIMARY KEY,
   user_name TEXT REFERENCES users,
   index_url TEXT,
   last_modified_url TEXT,
   local_stats_url TEXT,
   stats_url TEXT,
   mirrors_url TEXT
);

