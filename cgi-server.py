#!/usr/bin/python
# 

from CGIHTTPServer import CGIHTTPRequestHandler
import BaseHTTPServer, SimpleHTTPServer

def main ():
    SimpleHTTPServer.test(CGIHTTPRequestHandler, BaseHTTPServer.HTTPServer)

if __name__ == '__main__':
    main()