import hashlib
import os
import secrets
import socket
import random
from binascii import unhexlify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("192.168.8.196", 9000))  # Listen for connection to the port
s.listen(5)
print("\nWaiting for client ...\n")
(c, a) = s.accept()  # Accept the connection from client
print("Received connection from", a)  # Print the connection information

k = unhexlify('7d72678b273de321f7bd67e3182dd316ac0fdfdc454989e557cc40c86b79d682')  # Hashed key (SHA256) of student ID
SPACE = b'<SPACE>'  # Bytes Separator
select = 0  # Used for new round loop
# Server p and q (Bob)
p2 = 2357111317192329313741434753596167717379838997101103107109113127131137139149151157163167173179181191193197199211223227229233239241251257263269271277281283293307311313317331337347349353359367373379383389397401409419421431433439443449457461463467479487491499503509521523541547557563569571577587593599601607613617619631641643647653659661673677683691701709719
q2 = 7891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891
S = (p2 - 1) * (q2 - 1)  # (p-1)(q-1)
# Server public key
N2 = p2 * q2
e2 = 7
# Server Private keyS
d2 = pow(e2, -1, S)
# Client public Key (Alice)
N1 = 9817766666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666670379887169999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999874799999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999581325509666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666555969
e1 = 7

# Generator g
g = 2
# Prime number m from 2048-bit MODP Group
m = int(
    '0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF',
    base=16)


def authentication():
    global Session_key, Alice, Sa, H_int

    # Generate new secure random number in integer
    b = secrets.randbits(2048)
    print("b= ", b)  # print test
    # Random Rb in bytes
    Rb = os.urandom(32)
    # Kb = g^a mod m
    Kb = pow(g, b, m)
    Kb = str(Kb).encode()
    # Make Bob IP his ID
    Bob = socket.gethostbyname(socket.gethostname())
    Bob = str.encode(Bob)

    # ************ Greetings ************
    hello = c.recv(10000).decode()
    print(hello)
    greetings = "\nGreetings! I am server\n"
    c.send(greetings.encode())
    game = c.recv(10000).decode()
    print(game)
    ready = "Ready For The Guess Game!\n"
    c.send(ready.encode())

    # Step 1 of authentication
    c.send(Bob)
    Alice, Ra, Ka = c.recv(10000).split(SPACE)
    print("Ra= ", Ra.hex())                     # print test
    print("Rb= ", Rb.hex())                     # print test
    # Session key K = g^ab mod m
    K = pow(int(Ka.decode()), b, m)
    K = str(K).encode()
    # New object to construct the hash H
    H = hashlib.sha256()
    # hash (Alice, Bob, Ra, Rb, Ka, Kb, K)
    H.update(Alice)
    H.update(Bob)
    H.update(Ra)
    H.update(Rb)
    H.update(Ka)
    H.update(Kb)
    H.update(K)
    # Integer value of the hash
    H_int = int.from_bytes(H.digest(), 'big')

    # Bob signature
    Sb = pow(H_int, d2, N2)
    Sb = str(Sb).encode()
    # Session key
    Session_key = hashlib.sha256()
    Session_key.update(K)
    Session_key = Session_key.digest()
    print("K: ", Session_key.hex())             # print test
    # Step 2 of authentication
    c.send(Rb + SPACE + Kb + SPACE + Sb)
    # Delete b for PFS
    b = 0


# ***********************************
while select != 2:
    authentication()
    k = Session_key                                 # Replace the hardcoded key with new one
    random_number = random.randint(1, 100)          # Generate random number for the client to guess
    print("The random number is: ", random_number)  # Print the random number of the server admin
    # Step 3 of authentication
    IV, ciphertext = c.recv(10000).split(SPACE)     # Receive IV and Ciphertext from the client
    cipher = AES.new(k, AES.MODE_CBC, iv=IV)        # Prepare new AES object to Decrypt

    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)  # Decrypt client choice
    select, Sa = plaintext.split(Alice)
    Sa = int(Sa.decode())
    select = int(select)                            # Convert the choice to integrate

    H1 = pow(Sa, e1, N1)

    if H1 != H_int:
        print("Not Alice. We've been compromised, burn everything!")
        select = 2
        break
    while select == 1:
        print("All clear, we are talking to Alice.")
        guess = c.recv(10000)                                   # Receive the encrypted guess
        cipher = AES.new(k, AES.MODE_CBC, iv=IV)                # New AES object
        guess = unpad(cipher.decrypt(guess), AES.block_size)    # Decrypt the guess received
        guess = int(guess)                                      # Convert the guess to integrate

        print("Guess:", guess)
        print("IV:", IV.hex())

        cipher1 = AES.new(k, AES.MODE_CBC, iv=IV)               # New AES object to Encrypt

        if guess < random_number:
            far_message = "Higher!"
            far_message = far_message.encode()                  # Encode the guess
            far_message = cipher1.encrypt(pad(far_message, AES.block_size))  # Encrypt the guess
            c.send(far_message)

        if guess > random_number:
            far_message = "Lower!"
            far_message = far_message.encode()                  # Encode the guess
            far_message = cipher1.encrypt(pad(far_message, AES.block_size))  # Encrypt the guess
            c.send(far_message)

        if guess == random_number:
            correct_message = "Correct!"
            far_message = correct_message.encode()              # Encode the guess
            far_message = cipher1.encrypt(pad(far_message, AES.block_size))  # Encrypt the guess
            c.send(far_message)
            k = 0  # Decrypt session key (k) for PFS
            select = 0
if select == 2:
    # ************ Closing ************
    print("Closing connection!")
    c.close()