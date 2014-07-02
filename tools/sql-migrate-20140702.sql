INSERT INTO accounts_user (password, last_login, is_superuser, username, name,
    is_staff, is_active, date_joined)
VALUES ('!', now(), false, 'deleted-user', 'deleted user', false, false, now());