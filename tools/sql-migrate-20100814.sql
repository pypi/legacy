BEGIN;
CREATE TABLE release_dependencies (
   name TEXT,
   version TEXT,
   kind INTEGER,
   specifier TEXT,
   FOREIGN KEY (name, version) REFERENCES releases (name, version)  ON UPDATE CASCADE
);
grant all on release_dependencies to pypi;

insert into release_dependencies(name, version, kind, specifier)
  select name, version, 1, specifier from release_requires;
insert into release_dependencies(name, version, kind, specifier)
  select name, version, 2, specifier from release_provides;
insert into release_dependencies(name, version, kind, specifier)
  select name, version, 3, specifier from release_obsoletes;
insert into release_dependencies(name, version, kind, specifier)
  select name, version, 4, specifier from release_requires_dist;
insert into release_dependencies(name, version, kind, specifier)
  select name, version, 5, specifier from release_provides_dist;
insert into release_dependencies(name, version, kind, specifier)
  select name, version, 6, specifier from release_obsoletes_dist;
insert into release_dependencies(name, version, kind, specifier)
  select name, version, 7, specifier from release_requires_external;
insert into release_dependencies(name, version, kind, specifier)
  select name, version, 8, specifier from release_project_url;

CREATE INDEX rel_dep_name_idx ON release_dependencies(name);
CREATE INDEX rel_dep_name_version_idx ON release_dependencies(name, version);
CREATE INDEX rel_dep_name_version_kind_idx ON release_dependencies(name, version, kind);

drop table release_requires;
drop table release_provides;
drop table release_obsoletes;
drop table release_requires_dist;
drop table release_provides_dist;
drop table release_obsoletes_dist;
drop table release_requires_external;
drop table release_project_url;

COMMIT;
