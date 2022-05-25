In this project (Phase3) I used my physical machine and Virtual machine (Oracle VirtualBox), and used for both OS I used PyCharm IDE.

Phusical Machine:
	OS: Windows 10 
	Python Interpreter: 3.10

Virtual machine:
	OS: Kali linux (Debian)
	Python Interpreter: 3.9
	Network: Bridged Adapter


Steps test: 
	0- Change the IP address to your device IP.
	1- Make sure virtual machine network are in Bridged Adapter mode.
	2- Run the Server.py script on a virtual machine.
	3- Run Client.py script on another machine (physical).
	4- Select 1 to start the game (type 1 on client side).
	5- Type a number below the correct answer (peek on the Server side to see the correct answer :) .
	6- Type 2 to quit the game and close the connection.
	7- Repeat the same steps with changing the key (to simulate Trudy attack).


* A guessing game that uses SHA256 hash function as a key in AES cryptosystem (CBC mode) to exchange secure messages between Server and Client. 
  RSA (ASymmetric) is used to authenticate server and client to each other & AES Symmetric is used as a session key.

* Phase3 achieves mutual authentication, perfect forward secrecy (PFS), and immune against man-in-the-middle (MiM) attacks.

* Make sure you don't have another library that conflicts with "Crypto"

* Requirements to run the project:
1. Python.
2. Python Socket package.
3. Python OS package.
4. Python hashlib package.
6. Python secrets package.
7. Python random package.
8. Python Crypto package.
