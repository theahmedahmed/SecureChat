from Crypto.Cipher import DES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import random
import string
import socket
import threading

keyPairB = RSA.generate(1024)
charList = string.ascii_lowercase + string.digits
idb = "RESPONDER B"
nonceList = []

def generate_key():
    result = ''
    for i in range(8):
        result = result + random.choice(charList)
    return result

def append_space_padding(text, blocksize=8):
    while len(text) % blocksize != 0:
        text += ' '
    return text

def des_encrypt(plaintext, key):
    byteKey = str.encode(key)
    des = DES.new(byteKey, DES.MODE_ECB)
    cypher = des.encrypt(str.encode(append_space_padding(plaintext)))
    return cypher

def des_decrypt(ciphertext, key):
    byteKey = str.encode(key)
    des = DES.new(byteKey, DES.MODE_ECB)
    plain = des.decrypt(ciphertext).decode()
    return plain

def rsa_encrypt(plain, key):
    encryptor = PKCS1_OAEP.new(key)
    cypher = encryptor.encrypt(str.encode(plain))
    return cypher

def rsa_decrypt(cypher, key):
    decryptor = PKCS1_OAEP.new(key)
    plaintext = decryptor.decrypt(cypher)
    return plaintext

def handle_recv(sock, key):
    while True:
        msg = sock.recv(1024)
        print(f'\nCypher received: {msg}')
        print(f'Message received: {des_decrypt(msg, key)}')
        print('Enter a message: ')

if __name__ == '__main__':
    s = socket.socket()             # Create a socket object
    port = 60000                    # Reserve a port for your service.

    s.connect(('127.0.0.1', port))

    print('Key distribution messages:')

    msg = s.recv(1024)
    pubKeyA = RSA.importKey(msg)
    s.send(keyPairB.publickey().exportKey(format='PEM', passphrase=None, pkcs=1))

    msg = rsa_decrypt(s.recv(1024), keyPairB)
    print(f'Message 1: {msg}')
    nonceList.append(msg.decode().split('|')[-1])

    msgToSend = f'{nonceList[0]}|{generate_key()}'
    cypherMsg = rsa_encrypt(msgToSend, pubKeyA)
    s.send(cypherMsg)

    msg = rsa_decrypt(s.recv(1024), keyPairB)
    while msg.decode().split('|')[-1] in nonceList:
        msg = rsa_decrypt(s.recv(1024), keyPairB)
    print(f'Message 3: {msg}')
    nonceList.append(msg.decode())

    msg = rsa_decrypt(s.recv(1024), keyPairB)
    while msg.decode() in nonceList:
        msg = rsa_decrypt(s.recv(1024), keyPairB)
    print(f'Message 4: {msg}')
    keyS = msg.decode()

    print('**Key distribution messages end here**\n')

    thread1 = threading.Thread(target=handle_recv, args=(s, keyS))
    thread1.start()

    while True:
        msgToSend = input('Enter a message: ')
        cypherMsg = des_encrypt(msgToSend, keyS)
        s.send(cypherMsg)
