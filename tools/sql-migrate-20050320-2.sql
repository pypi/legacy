
-- Table structure for table: release_provides
CREATE TABLE release_provides (
   name TEXT,
   version TEXT,
   specifier TEXT,
   FOREIGN KEY (name, version) REFERENCES releases (name, version)
);
CREATE INDEX rel_prov_name_idx ON release_provides(name);
CREATE INDEX rel_prov_version_id_idx ON release_provides(version);


-- Table structure for table: release_requires
CREATE TABLE release_requires (
   name TEXT,
   version TEXT,
   specifier TEXT,
   FOREIGN KEY (name, version) REFERENCES releases (name, version)
);
CREATE INDEX rel_req_name_idx ON release_requires(name);
CREATE INDEX rel_req_version_id_idx ON release_requires(version);


-- Table structure for table: release_obsoletes
CREATE TABLE release_obsoletes (
   name TEXT,
   version TEXT,
   specifier TEXT,
   FOREIGN KEY (name, version) REFERENCES releases (name, version)
);
CREATE INDEX rel_obs_name_idx ON release_obsoletes(name);
CREATE INDEX rel_obs_version_id_idx ON release_obsoletes(version);
