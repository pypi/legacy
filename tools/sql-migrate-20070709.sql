create index journals_latest_releases on journals(submitted_date, name, version) where version is not null and action='new release';
