begin;
-- OpenID tables

ALTER TABLE openids ADD CONSTRAINT openids_name_fkey FOREIGN KEY (name) REFERENCES users (name) ON DELETE CASCADE;

ALTER TABLE openid_stypes ADD CONSTRAINT openid_stypes_id_fkey FOREIGN KEY (id) REFERENCES openid_sessions ON DELETE CASCADE;

ALTER TABLE cookies ADD CONSTRAINT cookies_name_fkey FOREIGN KEY (name) REFERENCES users ON DELETE CASCADE;

ALTER TABLE sshkeys ADD CONSTRAINT sshkeys_name_fkey FOREIGN KEY (name) REFERENCES users ON DELETE CASCADE;

ALTER TABLE rego_otk ADD CONSTRAINT rego_otk_name_fkey FOREIGN KEY (name) REFERENCES users ON DELETE CASCADE;

ALTER TABLE journals ADD CONSTRAINT journals_submitted_by_fkey FOREIGN KEY (submitted_by) REFERENCES users ON DELETE CASCADE;

ALTER TABLE cheesecake_subindices ADD CONSTRAINT cheesecake_subindices_main_index_id_fkey FOREIGN KEY (main_index_id) REFERENCES cheesecake_main_indices;

ALTER TABLE releases ADD CONSTRAINT releases_name_fkey FOREIGN KEY (name) REFERENCES packages ON DELETE CASCADE;

ALTER TABLE releases ADD CONSTRAINT releases_cheesecake_installability_id_fkey FOREIGN KEY (cheesecake_installability_id) REFERENCES cheesecake_main_indices; 

ALTER TABLE releases ADD CONSTRAINT releases_cheesecake_documentation_id_fkey FOREIGN KEY (cheesecake_documentation_id) REFERENCES cheesecake_main_indices;

ALTER TABLE releases ADD CONSTRAINT releases_cheesecake_code_kwalitee_id_fkey FOREIGN KEY (cheesecake_code_kwalitee_id) REFERENCES cheesecake_main_indices; 

ALTER TABLE release_classifiers ADD CONSTRAINT release_classifiers_trove_id_fkey FOREIGN KEY (trove_id) REFERENCES trove_classifiers;

ALTER TABLE release_classifiers ADD CONSTRAINT release_classifiers_name_fkey FOREIGN KEY (name, version) REFERENCES releases (name, version);

ALTER TABLE release_dependencies ADD CONSTRAINT release_dependencies_name_fkey FOREIGN KEY (name, version) REFERENCES releases (name, version) ON UPDATE CASCADE;

ALTER TABLE release_files ADD CONSTRAINT release_files_name_fkey FOREIGN KEY (name, version) REFERENCES releases (name, version) ON UPDATE CASCADE;

ALTER TABLE release_urls ADD CONSTRAINT release_urls_name_fkey FOREIGN KEY (name, version) REFERENCES releases (name, version) ON UPDATE CASCADE;

ALTER TABLE description_urls ADD CONSTRAINT description_urls_name_fkey FOREIGN KEY (name, version) REFERENCES releases (name, version) ON UPDATE CASCADE;

ALTER TABLE roles ADD CONSTRAINT roles_user_name_fkey FOREIGN KEY (user_name) REFERENCES users;
ALTER TABLE roles ADD CONSTRAINT roles_package_name_fkey FOREIGN KEY (package_name) REFERENCES packages ON UPDATE CASCADE;

ALTER TABLE mirrors ADD CONSTRAINT mirrors_user_name_fkey FOREIGN KEY (user_name) REFERENCES users;

ALTER TABLE ratings ADD CONSTRAINT ratings_user_name_fkey FOREIGN KEY (user_name) REFERENCES users ON DELETE CASCADE;

ALTER TABLE ratings ADD CONSTRAINT ratings_name_fkey FOREIGN KEY (name, version) REFERENCES releases ON UPDATE CASCADE ON DELETE CASCADE;

ALTER TABLE comments ADD CONSTRAINT comments_rating_fkey FOREIGN KEY (rating) REFERENCES ratings (id) ON DELETE CASCADE;

ALTER TABLE comments ADD CONSTRAINT comments_user_name_fkey FOREIGN KEY (user_name) REFERENCES users ON DELETE CASCADE;

ALTER TABLE comments ADD CONSTRAINT comments_in_reply_to_fkey FOREIGN KEY (in_reply_to) REFERENCES comments ON DELETE CASCADE;

ALTER TABLE comments_journal ADD CONSTRAINT comments_journal_submitted_by_fkey FOREIGN KEY (submitted_by) REFERENCES users ON DELETE CASCADE;

ALTER TABLE comments_journal ADD CONSTRAINT comments_journal_name_fkey FOREIGN KEY (name, version) REFERENCES releases ON UPDATE CASCADE ON DELETE CASCADE;
