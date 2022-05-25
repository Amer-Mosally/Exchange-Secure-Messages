import hashlib
import os
import socket
import secrets
from binascii import unhexlify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('192.168.8.196', 9000))
print("Connecting ...")

# Hashed key (SHA256) of student ID
k = unhexlify('7d72678b273de321f7bd67e3182dd316ac0fdfdc454989e557cc40c86b79d682')
# Bytes Separator
SPACE = b'<SPACE>'
# Used for new round loop
flag = True
# Server public Key (Bob)
N2 = 18600518306595749554093242385656405360600503501760468154703283354470186399023497005093473361142533049588258424899067895485126275286436374245797866335095271900392543636721256932967678874590770791138584985041296561244544496176772171992296505142679256710463265298780442834415356516544586116742039056782450065014588551676733559564302581596979814376828519293773627079783101043054599237385134079657986006778516445908908314135796748416634758495258784828565712531440656490874572994933197980457279232839935728111316981275432350845787064220237286947979566378111754873580374664092433444480890447354737445525038105314571463395605687833409440171955552559118824294420400646882264818964830441746626775701356207596878880032629
e2 = 7
# Client p and q (Alice)
p1 = 3130000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001183811000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000313
q1 = 3136666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666313
S = (p1 - 1) * (q1 - 1)  # S = (p-1)(q-1)
# Client public key
N1 = p1 * q1
e1 = 7
# Client Private key
d1 = pow(e1, -1, S)

# Generator g
g = 2
# Prime number m from 2048-bit MODP Group
m = int(
    '0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF',
    base=16)


def authentication():
    global Session_key, Alice, Sa, flag

    # Generate new secure random number in integer
    a = secrets.randbits(2048)
    print("a= ", a)  # print test
    # Random Ra in bytes
    Ra = os.urandom(32)
    # Ka = g^a mod m
    Ka = pow(g, a, m)
    Ka = str(Ka).encode()
    # Make Alice IP her ID
    Alice = socket.gethostbyname(socket.gethostname())
    Alice = str.encode(Alice)

    # ************ Greetings ************
    hello = "Hello I am Client\n"
    s.send(hello.encode())
    greetings = s.recv(10000).decode()
    print(greetings)
    game = "Guess Game Please\n"
    s.send(game.encode())
    game = s.recv(10000).decode()
    print(game)

    # Step 1 of authentication
    Bob = s.recv(10000)
    s.send(Alice + SPACE + Ra + SPACE + Ka)
    # Step 2 of authentication
    Rb, Kb, Sb = s.recv(10000).split(SPACE)  # ******may not work split
    print("Ra= ", Ra.hex())  # print test
    print("Rb= ", Rb.hex())  # print test

    Sb = int(Sb.decode())
    # Session key K = g^ab mod m
    K = pow(int(Kb.decode()), a, m)
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

    # Alice signature
    Sa = pow(H_int, d1, N1)
    Sa = str(Sa).encode()
    # Session key
    Session_key = hashlib.sha256()
    Session_key.update(K)
    Session_key = Session_key.digest()
    print("K: ", Session_key.hex())  # print test
    # Decrypt Sb
    H2 = pow(Sb, e2, N2)
    # Delete a for PFS
    a = 0

    if H2 != H_int:
        print("Not Bob. We've been compromised, burn everything!")
        flag = False


# **********************************
while flag:  # Starting of new round
    authentication()
    select = 0
    if flag:
        print("All clear, we are talking to Bob.")
        k = Session_key  # Replace the hardcoded key with new one

        select = input("1-Start a guessing game round \n2-Quit the guessing game application \n")

        IV = os.urandom(16)                                 # Generate new secure random number in bytes
        cipher = AES.new(k, AES.MODE_CBC, iv=IV)            # Prepare new AES object to Encrypt
        plaintext = select.encode()  # Encode select
        ciphertext = cipher.encrypt(
            pad(plaintext + Alice + Sa, AES.block_size))    # Encrypt the text (select + Alice + Sa)
        select = int(select)  # Convert select to int
        # Step 3 of authentication
        s.send(IV + SPACE + ciphertext)                     # Send IV and (select + Alice + Sa)

        while select == 1:
            cipher = AES.new(k, AES.MODE_CBC, iv=IV)        # New AES object

            guess = input("Enter your guess (between 1 and 100): ")
            guess = guess.encode()  # Encode the guess
            guess = cipher.encrypt(pad(guess, AES.block_size))  # Encrypt the guess

            print("IV: ", IV.hex())
            s.send(guess)  # Send the guess to server

            cipher1 = AES.new(k, AES.MODE_CBC, iv=IV)                               # New object to decrypt
            response = s.recv(10000)                                                # Receive the encrypted response
            response = unpad(cipher1.decrypt(response), AES.block_size).decode()    # Decrypt the response
            print(response)                                                         # Print the response

            if response.startswith("Correct"):
                k = 0       # Decrypt session key (k) for PFS
                select = 0  # If it's correct end the round

    if select == 2 or not flag:  # Close the connection
        # ************ Closing ************
        print("Closing connection!")
        s.close()
        break