
serve:
	if [ ! -e cgi-bin ] ; then ln -s . cgi-bin ; fi
	python cgi-server.py &

sshkeys_update:	sshkeys_update.c
	cc -o sshkeys_update sshkeys_update.c
	chown submit sshkeys_update
	chmod +s sshkeys_update
