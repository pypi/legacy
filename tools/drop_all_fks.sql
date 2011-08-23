/*

File Name  : drop_all_fks.sql
Description: Drop all foreign keys for a PYPI database to allow pg_restore to
             be run and clone the database
*/

ALTER TABLE openids DROP CONSTRAINT openids_name_fkey;
ALTER TABLE openid_stypes DROP CONSTRAINT openid_stypes_id_fkey;
ALTER TABLE cookies DROP CONSTRAINT cookies_name_fkey;
ALTER TABLE sshkeys DROP CONSTRAINT sshkeys_name_fkey;
ALTER TABLE rego_otk DROP CONSTRAINT rego_otk_name_fkey;
ALTER TABLE journals DROP CONSTRAINT journals_submitted_by_fkey;
ALTER TABLE cheesecake_subindices DROP CONSTRAINT cheesecake_subindices_main_index_id_fkey;
ALTER TABLE releases DROP CONSTRAINT releases_name_fkey;
ALTER TABLE releases DROP CONSTRAINT releases_cheesecake_installability_id_fkey;
ALTER TABLE releases DROP CONSTRAINT releases_cheesecake_documentation_id_fkey;
ALTER TABLE releases DROP CONSTRAINT releases_cheesecake_code_kwalitee_id_fkey;
ALTER TABLE release_classifiers DROP CONSTRAINT release_classifiers_trove_id_fkey;
ALTER TABLE release_classifiers DROP CONSTRAINT release_classifiers_name_fkey;
ALTER TABLE release_dependencies DROP CONSTRAINT release_dependencies_name_fkey;
ALTER TABLE release_files DROP CONSTRAINT release_files_name_fkey;
ALTER TABLE release_urls DROP CONSTRAINT release_urls_name_fkey;
ALTER TABLE description_urls DROP CONSTRAINT description_urls_name_fkey;
ALTER TABLE roles DROP CONSTRAINT roles_user_name_fkey;
ALTER TABLE roles DROP CONSTRAINT roles_package_name_fkey;
ALTER TABLE mirrors DROP CONSTRAINT mirrors_user_name_fkey;
ALTER TABLE ratings DROP CONSTRAINT ratings_user_name_fkey;
ALTER TABLE ratings DROP CONSTRAINT ratings_name_fkey;
ALTER TABLE comments DROP CONSTRAINT comments_rating_fkey;
ALTER TABLE comments DROP CONSTRAINT comments_user_name_fkey;
ALTER TABLE comments DROP CONSTRAINT comments_in_reply_to_fkey;
ALTER TABLE comments_journal DROP CONSTRAINT comments_journal_submitted_by_fkey;
ALTER TABLE comments_journal DROP CONSTRAINT comments_journal_name_fkey;

