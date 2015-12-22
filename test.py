import BaseHTTPServer
import SimpleHTTPServer
import SocketServer
import logging
import cgi
import ssl
import os
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto import Random


PORT = 8002

Handler = SimpleHTTPServer.SimpleHTTPRequestHandler

httpd = SocketServer.TCPServer(("", PORT), Handler)

print "serving at port", PORT
httpd.socket = ssl.wrap_socket (httpd.socket, certfile='/root/fenrir/cert.pem', server_side=True)
httpd.serve_forever()
