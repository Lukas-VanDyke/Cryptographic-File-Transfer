import sys
import socketserver
import socket, threading
import time
import random
import string
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

global key
key = ""

def decryption(cipher, iv, ciphertext, key):
	#No cipher used
	if cipher == 0:
		return ciphertext
	#aes-128 or 256 used
	elif cipher == 1 or cipher == 2:
		#Decrypt data
		backend = default_backend()
		cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
		decryptor = cipher.decryptor()
		paddedPlainText = decryptor.update(ciphertext) + decryptor.finalize()
		#Unpad data
		unpadder = padding.PKCS7(128).unpadder()
		plaintext = unpadder.update(paddedPlainText) + unpadder.finalize()
		return plaintext
		
def encryption(cipher, iv, plaintext, key):
	#No cipher used
	if cipher == 0:
		return plaintext
	#aes-128 or 256 used
	elif cipher == 1 or cipher == 2:
		#Pad data
		padder = padding.PKCS7(128).padder()
		paddedPlainText = padder.update(plaintext) + padder.finalize()
		#Encrypt data
		backend = default_backend()
		cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
		encryptor = cipher.encryptor()
		ciphertext = encryptor.update(paddedPlainText) + encryptor.finalize()
		return ciphertext

class TCPRequestHandler(socketserver.BaseRequestHandler):
	BUFFER_SIZE = 4096
	validCiphers = ["none", "aes-128", "aes-256"]
	iv = None
	cipher = None
	command = None
	
	def handle(self):
		data = self.request.recv(self.BUFFER_SIZE)
		
		for i in range(len(self.validCiphers)):
			elem = self.validCiphers[i]
			byteCipher = bytes(elem, "utf-8")
			if (data.startswith(byteCipher)):
				self.iv = data[len(elem):]
				self.cipher = i 
				break
		
		if self.cipher == 0:
			print(time.strftime("%H:%M:%S") + ": " + "New client using crypto: " + self.validCiphers[self.cipher])
			realKey = key
		elif self.cipher == 1:
			print(time.strftime("%H:%M:%S") + ": " + "New client using crypto: " + self.validCiphers[self.cipher] + " and iv: " + self.iv.decode("utf-8"))
			realKey = bytes(key, "utf-8")
			while len(realKey)*8 < 128:
				realKey = realKey + realKey
			if len(realKey)*8 >128:
				realKey = realKey[:16]
		elif self.cipher == 2:
			print(time.strftime("%H:%M:%S") + ": " + "New client using crypto: " + self.validCiphers[self.cipher] + " and iv: " + self.iv.decode("utf-8"))
			realKey = bytes(key, "utf-8")
			while len(realKey)*8 < 256:
				realKey = realKey + realKey
			if len(realKey)*8 > 256:
				realKey = realKey[:32]
			
		
		encryptedAck = encryption(self.cipher, self.iv, bytes("Ready", "utf-8"), realKey)
		encryptedFinished = encryption(self.cipher, self.iv, bytes("Finished", "utf-8"), realKey)
		
		#Verify key
		encryptedCipher = encryption(self.cipher, self.iv, bytes(self.validCiphers[self.cipher], "utf-8"), realKey)
		self.request.sendall(encryptedCipher)
		encryptedCipher = self.request.recv(self.BUFFER_SIZE)
		try:
			decryptedCipher = decryption(self.cipher, self.iv, encryptedCipher, realKey)
			sameKeys = True
			if decryptedCipher == bytes(self.validCiphers[self.cipher], "utf-8"):
				self.request.sendall(encryptedAck)
		except ValueError:
			print(time.strftime("%H:%M:%S") + ": " + "Error, incorrect keys")
			sameKeys = False
		
		if sameKeys:
			#Receive command
			encCommand = self.request.recv(self.BUFFER_SIZE)
			decCommand = decryption(self.cipher, self.iv, encCommand, realKey)
			if decCommand == bytes("write", "utf-8"):
				self.command = "write"
			else:
				self.command = "read"
			self.request.sendall(encryptedAck)
			
			#Receive filename
			encFilename = self.request.recv(self.BUFFER_SIZE)
			decFilename = decryption(self.cipher, self.iv, encFilename, realKey)
			self.filename = decFilename.decode("utf-8")
			self.request.sendall(encryptedAck)
			
			print(time.strftime("%H:%M:%S") + ": " + self.command + " " + self.filename)
			
			if self.command == "write":
				#Open write file
				toWrite = open(self.filename, "wb")
				while True:
					#Receive data size
					encLength = self.request.recv(self.BUFFER_SIZE)
					#Decrypt data size
					strLength = decryption(self.cipher, self.iv, encLength, realKey).decode("utf-8")
					#Check if finished
					if strLength == "Finished":
						break
					length = int(strLength)
					#Send ack
					self.request.sendall(encryptedAck)
					#Receive data
					encData = self.request.recv(length)
					#Decrypt data
					decData = decryption(self.cipher, self.iv, encData, realKey)
					#Send ack
					self.request.sendall(encryptedAck)
					#Write data to filename
					toWrite.write(decData)
					#Repeat
				toWrite.close()
			else:
				#Wait for ack
				ack = self.request.recv(self.BUFFER_SIZE)
				#Open file to read
				try:
					toRead = open(self.filename, "rb")
					self.request.sendall(encryptedAck)
					#Wait for ack
					ack = self.request.recv(self.BUFFER_SIZE)
					while True:
						#Read from filename
						data = toRead.read(self.BUFFER_SIZE)
						#Check if EOF reached
						if data == b"":
							self.request.sendall(encryptedFinished)
							break
						#Encrypt data
						encData = encryption(self.cipher, self.iv, data, realKey)
						#Encrypt data size
						length = str(len(encData))
						encLength = encryption(self.cipher, self.iv, bytes(length, "utf-8"), realKey)
						#Send data size
						self.request.sendall(encLength)
						#Wait for ack
						self.request.recv(self.BUFFER_SIZE)
						#Send data
						self.request.sendall(encData)
						#Wait for ack
						self.request.recv(self.BUFFER_SIZE)
						#Repeat
					toRead.close()
				except FileNotFoundError:
					#File not found
					encError = encryption(self.cipher, self.iv, bytes("Error, file does not exist", "utf-8"), realKey)
					self.request.sendall(encError)
					print(time.strftime("%H:%M:%S") + ": " + "Error, file does not exist")
					
		print(time.strftime("%H:%M:%S") + ": " + "Done")
		self.server.shutdown()
		self.server.server_close()

if __name__ == "__main__":
	PORT = int(sys.argv[1])
	# Listen for clients on PORT
	print("Listening on port " + sys.argv[1])
	
	if len(sys.argv) == 3:
		key = sys.argv[2]
	else:
		# Generate 32 character long string for key
		key = ""
		for i in range(32):
			key += random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits)
			
	print("Using secret key: " + key)
	address = socket.gethostname()
	
	while True:
		# Handle client's read/write request
		socketserver.ThreadingTCPServer.allow_reuse_address = True
		server = socketserver.ThreadingTCPServer(("localhost",PORT), TCPRequestHandler)
		server.serve_forever()
