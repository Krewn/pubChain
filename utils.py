from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives import hashes
from hashlib import sha256
from cryptography.hazmat.primitives.asymmetric import padding
import os

hash = lambda b : sha256(b).digest()

def verify(signatureFile,publicKeyFile,contentFile):
	if type(signatureFile) == str:
		with open(signatureFile,"rb") as _signatureFile:
			signature = _signatureFile.read()
	elif type(signatureFile) == bytes:
		signature = signatureFile
	else:
		raise TypeError
	if type(contentFile) == str:
		with open(contentFile,"rb") as _contentFile:
			content = _contentFile.read()
	elif type(contentFile) == bytes:
		content = contentFile
	else:
		raise TypeError
	if type(publicKeyFile) == str:
		with open(publicKeyFile,"rb") as _publicKeyFile:
			public_key = serialization.load_ssh_public_key(_publicKeyFile.read())
	elif type(publicKeyFile) == bytes:
		public_key = serialization.load_ssh_public_key(publicKeyFile)
	else:
		raise TypeError
	public_key.verify(
		signature,
		content,
		padding.PSS(
			mgf=padding.MGF1(hashes.SHA256()),
			salt_length=padding.PSS.MAX_LENGTH
			),
		hashes.SHA256()
	)

class rsaKeyPair():
	def __init__(self):
		self.key = rsa.generate_private_key(
			backend=crypto_default_backend(),
			public_exponent=65537,
			key_size=2048
		)
		self.refresh()
	def refresh(self):
		self.privateKey = self.key.private_bytes(
			serialization.Encoding.PEM,
			serialization.PrivateFormat.PKCS8,
			serialization.NoEncryption()
		)
		self.publicKey = self.key.public_key().public_bytes(
			serialization.Encoding.OpenSSH,
			serialization.PublicFormat.OpenSSH
		)
		self.publicKeyHash = hash(self.publicKey)
	def write(self):
		keyNumber = str(int.from_bytes(self.publicKeyHash,"big"))
		os.mkdir(keyNumber)
		os.chdir(keyNumber)
		with open(f"{keyNumber}.pub","wb") as publicKeyFile:
			publicKeyFile.write(self.publicKey)
		with open(f"{keyNumber}.rsa","wb") as autographFile:
			autographFile.write(self.sign(self.publicKey))
		with open(f"{keyNumber}.pem","wb") as privateKeyFile:
			privateKeyFile.write(self.privateKey)
		verify(f"{keyNumber}.rsa",f"{keyNumber}.pub",f"{keyNumber}.pub")
		os.chdir("..")
	def load(self,fn):
		with open(fn, "rb") as key_file:
			self.key = serialization.load_pem_private_key(
			key_file.read(),
			password=None,
		)
		self.refresh()
	def sign(self,message):
		#serialization.load_pem_private_key(self.privateKey,password=None)
		return self.key.sign(
						message,
						padding.PSS(
							mgf=padding.MGF1(hashes.SHA256()),
							salt_length=padding.PSS.MAX_LENGTH),
							hashes.SHA256()
						)

