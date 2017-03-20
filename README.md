# Cryptographic-File-Transfer
A client and server that allow encrypted or unecnrypted file transfer.

How to run:

First, run the server:
python3 server.py *port secretkey

Then run the client:
python3 client.py *command filename address:port cipher sercretkey

Port is the port number the server will listen on.

Secret Key is an optional key, a random key will be generated if no key is given.

Command can be either read or write.

Filename is the name of the file to be written to or read from.

Address:port is the address of the server and the port the server is listening on, separated by a colon.

Cipher is either none, aes-128, or aes-256, which specifies the type of encryption to be used.

Secret Key is an optional key, a random key will be generated if no key is given.
