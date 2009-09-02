-- run as a cronjob: psql packages -f tools/daily.sql -o /dev/null
delete from cookies where last_seen < now()-INTERVAL'1day';
delete from openid_sessions where expires < now();