import socket
import sys
import os
import random
import string
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

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

if __name__ == "__main__":
	BUFFER_SIZE = 4096
	command = sys.argv[1]
	# Check validity of command (read, write)
	filename = sys.argv[2]
	host_port = sys.argv[3]
	serv_info = host_port.split(":")
	HOST, PORT = serv_info[0], int(serv_info[1])
	
	validCiphers = ["none", "aes-128", "aes-256"]
	string_cipher = sys.argv[4]
	cipher = -1
	for i in range(len(validCiphers)):
		elem = validCiphers[i]
		if string_cipher == elem:
			cipher = i
	
	# Check validity of cipher (aes256, aes128, none)
	if ( len(sys.argv) == 6 and string_cipher != "none" ):
		key = sys.argv[5]
	else:
		key = "No key"
		
	if cipher == 0:
		pass
	elif cipher == 1:
		key = bytes(key, "utf-8")
		while len(key)*8 < 128:
			key = key + key
		if len(key)*8 > 128:
			key = key[:16]
	elif cipher == 2:
		key = bytes(key, "utf-8")
		while len(key)*8 < 256:
			key = key + key
		if len(key)*8 > 256:
			key = key[:32]
		
	# Attempt to connect to server
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		if cipher == -1:
			sys.stderr.write("Error, invalid cipher type\n")
			raise OSError
		sock.connect((HOST, PORT))
		
		iv = ""
		for i in range(16):
			iv += random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits)
		
		# Send cipher / IV
		cipher_bytes = bytes(string_cipher, "utf-8")
		iv = bytes(iv, "utf-8")
		initMsg = cipher_bytes + iv
		sock.sendall(initMsg)
		
		#Verify same key
		encryptedCipher = sock.recv(BUFFER_SIZE)
		try:
			decryptedCipher = decryption(cipher, iv, encryptedCipher, key)
			if decryptedCipher == bytes(validCiphers[cipher], "utf-8"):
				sock.sendall(encryptedCipher)
		except ValueError:
			encError = encryption(cipher, iv, bytes("Error, incorrect keys", "utf-8"), key)
			sys.stderr.write("Error, incorrect keys\n")
			sock.sendall(encError)
			sock.close()
				
		encryptedAck = sock.recv(BUFFER_SIZE) #Receive ack
		
		#Send command
		encCommand = encryption(cipher, iv, bytes(command, "utf-8"), key)
		sock.sendall(encCommand)
		encryptedAck = sock.recv(BUFFER_SIZE) #Receive ack
		
		#Send filename
		encFilename = encryption(cipher, iv, bytes(filename, "utf-8"), key)
		sock.sendall(encFilename)
		encryptedAck = sock.recv(BUFFER_SIZE) #Receive ack
		
		encryptedAck = encryption(cipher, iv, bytes("Ready", "utf-8"), key)
		encryptedFinished = encryption(cipher, iv, bytes("Finished", "utf-8"), key)
		
		if command == "write":
			while True:
				#Read from standard input
				data = sys.stdin.buffer.read(BUFFER_SIZE)
				#Check if EOF reached
				if len(data) == 0:
					sock.sendall(encryptedFinished)
					sys.stderr.write("OK\n")
					sock.close()
					break
				#Encrypt data
				encData = encryption(cipher, iv, data, key)
				#Encrypt data size
				length = str(len(encData))
				encLength = encryption(cipher, iv, bytes(length, "utf-8"), key)
				#Send data size
				sock.sendall(encLength)
				#Wait for ack
				encryptedAck = sock.recv(BUFFER_SIZE) #Receive ack
				#Send data
				sock.sendall(encData)
				#Wait for ack
				encryptedAck = sock.recv(BUFFER_SIZE) #Receive ack
				#Repeat
		else:
			#Send ack
			sock.sendall(encryptedAck)
			#Receive ack or error
			ackError = sock.recv(BUFFER_SIZE)
			if ackError == encryption(cipher, iv, bytes("Error, file does not exist", "utf-8"), key):
				sys.stderr.write("Error, file does not exist\n")
				sock.close()
			#Send ack
			sock.sendall(encryptedAck)
			while True:
				#Receive data size
				encLength = sock.recv(BUFFER_SIZE)
				#Decrypt data size
				strLength = decryption(cipher, iv, encLength, key).decode("utf-8")
				#Check if finished
				if strLength == "Finished":
					sys.stderr.write("OK\n") 
					sock.close()
					break
				length = int(strLength)
				#Send ack
				sock.sendall(encryptedAck)
				#Receive data
				encData = sock.recv(length)
				#Decrypt data
				decData = decryption(cipher, iv, encData, key)
				#Send ack
				sock.sendall(encryptedAck)
				#Write data to standard output
				sys.stdout.buffer.write(decData)
				#Repeat
	except OSError:
		pass
