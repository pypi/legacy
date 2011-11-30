begin;
alter table journals drop constraint "$1";
alter table journals add foreign key (submitted_by) references users (name) on update cascade;
end;
begin;
alter table roles drop constraint "$1";
alter table roles add foreign key (user_name) references users (name) on update cascade;
end;
