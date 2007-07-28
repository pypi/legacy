ALTER TABLE trove_classifiers ADD COLUMN l2 INTEGER;
ALTER TABLE trove_classifiers ADD COLUMN l3 INTEGER;
ALTER TABLE trove_classifiers ADD COLUMN l4 INTEGER;
ALTER TABLE trove_classifiers ADD COLUMN l5 INTEGER;

CREATE INDEX rel_class_name_version_idx ON release_classifiers(name, version);

-- run 'store.py config.ini checktrove' after installing this change
