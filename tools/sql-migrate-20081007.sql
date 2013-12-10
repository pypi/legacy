-- before running this, verify that the constraints
-- that get deleted are the same ones that get recreated
-- (with cascading update)
begin;
alter table releases drop constraint "$1";
alter table releases add foreign key (name) references packages(name) on update cascade;

alter table release_provides drop constraint "$1";
alter table release_provides add foreign key (name, version) references releases(name, version) on update cascade;

alter table release_requires drop constraint "$1";
alter table release_requires add foreign key (name, version) references releases(name, version) on update cascade;

alter table release_obsoletes drop constraint "$1";
alter table release_obsoletes add foreign key (name, version) references releases(name, version) on update cascade;

alter table release_files drop constraint "$1";
alter table release_files add foreign key (name, version) references releases(name, version) on update cascade;

alter table release_urls drop constraint "$1";
alter table release_urls add foreign key (name, version) references releases(name, version) on update cascade;

alter table description_urls drop constraint "$1";
alter table description_urls add foreign key (name, version) references releases(name, version) on update cascade;

alter table release_classifiers drop constraint "$2";
alter table release_classifiers add foreign key (name, version) references releases(name, version) on update cascade;

alter table roles drop constraint "$2";
alter table roles add foreign key (package_name) references packages(name) on update cascade;

commit;

