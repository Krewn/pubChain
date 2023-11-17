
from urllib import parse
from PIL import Image
import os
import utils

from wsgiref.simple_server import make_server
from pyramid.config import Configurator
from pyramid.response import Response
from pyramid.view import view_config
from pyramid.response import FileResponse
from pyramid.view import view_config
from pyramid.httpexceptions import HTTPFound

import hashlib
import time

class blockChain:
	def __init__(self,head = b"INITIAL"):
		self.blocks = []
		self.head = head
		self.data = b""
		self.data = b"[--------BEGIN PREVIOUS BLOCK HASH--------]"+self.head+b"[--------END PREVIOUS BLOCK HASH--------]"
		self.data += b"[--------BEGIN CHAIN START TIME--------]"+bytes(time.strftime(" %Y/%M/%D - %H:%M:%S "),"UTF-8")+b"[--------END CHAIN START TIME--------]"
		self.blockIndex = 0
		self.rsa = utils.rsaKeyPair()
		self.dataDirectory = "bc_"+str(int.from_bytes(self.rsa.publicKeyHash,"big"))
		os.mkdir(self.dataDirectory)
		self.add(b"[--------BEGIN CHAINAUTHOR.PUB--------]"+self.rsa.publicKey+b"[--------END CHAINAUTHOR.PUB--------]")
		self.mintBlock()
	def mintBlock(self):
		os.chdir(self.dataDirectory)
		self.data += b"[--------BEGIN BLOCK END TIME--------]"+bytes(time.strftime("%Y/%M/%D - %H:%M:%S"),"UTF-8")+b"[--------END BLOCK END TIME--------]"
		with open(f"block_{self.blockIndex}.bin","wb") as blockdata:
			blockdata.write(self.data)
		self.head = hashlib.sha256(self.data).digest()
		with open(f"head_{self.blockIndex}.bin","wb") as head:
			head.write(self.head)
		self.blocks.append(self.data)
		self.data = b"[--------BEGIN PREVIOUS BLOCK HASH--------]"+self.head+b"[--------END PREVIOUS BLOCK HASH--------]"
		self.data += b"[--------BEGIN BLOCK START TIME--------]"+bytes(time.strftime(" %Y/%M/%D - %H:%M:%S "),"UTF-8")+b"[--------END BLOCK START TIME--------]"
		self.blockIndex += 1
		os.chdir("..")
	def add(self,line):
		if type(line) == bytes:
			self.data+=line
		elif type(line) == str:
			self.data+=bytes(line,"UTF-8")
	def terminate(self):
		self.mintBlock()
		self.data += b"[--------CHAINAUTHOR.RSA START--------]"+self.rsa.sign(b"".join(self.blocks))+b"[--------CHAINAUTHOR.RSA END--------]"
		self.mintBlock()
		self.rsa = utils.rsaKeyPair()
		self.dataDirectory = "bc_"+str(int.from_bytes(self.rsa.publicKeyHash,"big"))
		os.mkdir(self.dataDirectory)
		self.add(b"[--------BEGIN CHAINAUTHOR.PUB--------]"+self.rsa.publicKey+b"[--------END CHAINAUTHOR.PUB--------]")
		self.mintBlock()
	def sync(self,headFile):
		with open(headFile,"rb") as head:
			self.head = head.read()

bc = blockChain()

def pending():
	return bc.data

def admin(request):
	data = dict(parse.parse_qsl(request.query_string))
	if "mint" in data.keys():
		bc.mintBlock()
	if "terminate" in data.keys():
		bc.terminate()
	return Response(content_type="text/html",body=bc.data)

def submitPublicKey(request):
	body = """
	<h3>Submit a public key for publication<h3>
	<form method="POST" action="http://localhost:6450/make" method="post" accept-charset="utf-8" enctype="multipart/form-data">
	  <label for="fname">Public key:</label><br>
	  <input type="file" id="PublicKey" name="PublicKey"><br>
	  <label for="fname">Public key signature (self signed)</label><br>
	  <input type="file" id="Signature" name="Signature"><br><br>
	  <input type="submit">
	</form>
	"""
	return Response(content_type="text/html",body=body)

def make(request):
	signature = request.POST["Signature"].file.read()
	publicKey = request.POST["PublicKey"].file.read()
	print(signature)
	print(publicKey)
	utils.verify(signature,publicKey,publicKey)
	try:
		utils.verify(signature,publicKey,publicKey)
	except:
		print("invalid signature")
		return Response(content_type="text/html",body="invalid signature")
	chainSig = bc.rsa.sign(publicKey)
	bc.add(b"[--------PUBLIC KEY & SIGNAGE START--------]"+
		publicKey+b"[--------PUBLIC KEY END--------]"+
		chainSig+b"[--------SIGNAGE END--------]")
	return Response(content_type="text/html",body="ok")

def getBlock(request):
	data = dict(parse.parse_qsl(request.query_string))
	if "n" in data.keys():
		try:
			n = int(data["n"])
		except TypeError:
			return Response(content_type="text/html",body=b"".join(bc.blocks))
		try:
			return Response(content_type="text/html",body = bc.blocks[n])
		except IndexError:
			return Response(content_type="text/html",body = f"No block {n} found in chain. Chain length = {len(bc.blocks)}")
	return Response(content_type="text/html",body=b"".join(bc.blocks))


if __name__ == '__main__':
    with Configurator() as config:
        config.add_route('top', r'/')
        config.add_view(submitPublicKey, route_name='top')
        config.add_route('admin', r'/admin')
        config.add_view(admin, route_name='admin')
        config.add_route('make', r'/make')
        config.add_view(make, route_name='make')
        config.add_route('block', r'/block')
        config.add_view(getBlock, route_name='block')
        config.scan('__main__')
        app = config.make_wsgi_app()
    try:
        port = int(os.environ['PORT'])
    except KeyError:
        port = 6450
    server = make_server('0.0.0.0', port , app)
    server.serve_forever()












