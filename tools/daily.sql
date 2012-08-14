-- run as a cronjob: psql packages -f tools/daily.sql -o /dev/null
delete from cookies where last_seen < now()-INTERVAL'1day';
delete from openid_sessions where expires < now();
delete from openid_nonces where created < now()-INTERVAL'1day'; 
delete from openids where name in (select name from rego_otk where date < now()-INTERVAL'7days');
delete from users where name in (select name from rego_otk where date < now()-INTERVAL'7days' and name not in (select user_name from roles));
