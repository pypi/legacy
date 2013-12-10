-- New fields
ALTER TABLE releases ADD COLUMN requires_python TEXT;

--
-- New tables
--

-- Table structure for table: release_requires_python
CREATE TABLE release_requires_python (
   name TEXT,
   version TEXT,
   specifier TEXT,
   FOREIGN KEY (name, version) REFERENCES releases (name, version) ON UPDATE CASCADE
);
CREATE INDEX rel_req_python_name_idx ON release_requires_python(name);
CREATE INDEX rel_req_python_version_id_idx ON release_requires_python(version);
CREATE INDEX rel_req_python_name_version_idx ON release_requires_python(name,version);

-- Table structure for table: release_requires_external
CREATE TABLE release_requires_external (
   name TEXT,
   version TEXT,
   specifier TEXT,
   FOREIGN KEY (name, version) REFERENCES releases (name, version) ON UPDATE CASCADE
);
CREATE INDEX rel_req_ext_name_idx ON release_requires_external(name);
CREATE INDEX rel_req_ext_version_id_idx ON release_requires_external(version);
CREATE INDEX rel_req_ext_name_version_idx ON release_requires_external(name,version);

-- Table structure for table: release_requires_dist
CREATE TABLE release_requires_dist (
   name TEXT,
   version TEXT,
   specifier TEXT,
   FOREIGN KEY (name, version) REFERENCES releases (name, version) ON UPDATE CASCADE
);
CREATE INDEX rel_req_dist_name_idx ON release_requires_dist(name);
CREATE INDEX rel_req_dist_version_id_idx ON release_requires_dist(version);
CREATE INDEX rel_req_dist_name_version_idx ON release_requires_dist(name,version);

-- Table structure for table: release_provides_dist
CREATE TABLE release_provides_dist (
   name TEXT,
   version TEXT,
   specifier TEXT,
   FOREIGN KEY (name, version) REFERENCES releases (name, version) ON UPDATE CASCADE
);
CREATE INDEX rel_prov_dist_name_idx ON release_provides_dist(name);
CREATE INDEX rel_prov_dist_version_id_idx ON release_provides_dist(version);
CREATE INDEX rel_prov_dist_name_version_idx ON release_provides_dist(name,version);

-- Table structure for table: release_obsoletes_dist
CREATE TABLE release_obsoletes_dist (
   name TEXT,
   version TEXT,
   specifier TEXT,
   FOREIGN KEY (name, version) REFERENCES releases (name, version) ON UPDATE CASCADE
);
CREATE INDEX rel_obs_dist_name_idx ON release_obsoletes_dist(name);
CREATE INDEX rel_obs_dist_version_id_idx ON release_obsoletes_dist(version);
CREATE INDEX rel_obs_dist_name_version_idx ON release_obsoletes_dist(name,version);

-- Table structure for table: release_project_url
CREATE TABLE release_project_url (
   name TEXT,
   version TEXT,
   specifier TEXT,
   FOREIGN KEY (name, version) REFERENCES releases (name, version) ON UPDATE CASCADE
);
CREATE INDEX rel_proj_url_name_idx ON release_project_url(name);
CREATE INDEX rel_proj_url_version_id_idx ON release_project_url(version);
CREATE INDEX rel_proj_url_name_version_idx ON release_project_url(name,version);


