begin;
alter table comments_journal drop constraint comments_journal_name_fkey;
alter table comments_journal 
  add foreign key (name, version) references releases 
  on update cascade on delete cascade;
end;
