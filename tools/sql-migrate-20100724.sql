begin;
alter table ratings drop constraint ratings_pkey;
alter table ratings add primary key (id);
alter table ratings add unique(name,version,user_name);
end;