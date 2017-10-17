
serve:
	if [ ! -e cgi-bin ] ; then ln -s . cgi-bin ; fi
	python cgi-server.py &
