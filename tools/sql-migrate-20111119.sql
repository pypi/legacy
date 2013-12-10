CREATE TABLE openid_discovered (
    created TIMESTAMP,
    url TEXT PRIMARY KEY,
    services BYTEA,
    op_endpoint TEXT,
    op_local TEXT
);
alter table openid_sessions drop provider;
drop table openid_stypes;


