begin;
alter table journals drop constraint "$1";
alter table journals add foreign key (submitted_by) references users (name) on update cascade;
end;
