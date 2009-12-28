CREATE INDEX rel_req_name_version_idx ON release_requires (name,version);
CREATE INDEX rel_prov_name_version_idx ON release_provides (name,version);
CREATE INDEX rel_obs_name_version_idx ON release_obsoletes (name,version);
CREATE INDEX release_files_name_version_idx ON release_files(name,version);
