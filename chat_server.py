from Crypto.Cipher import DES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import random
import string
import socket
import threading

keyPairA = RSA.generate(1024)
charList = string.ascii_lowercase + string.digits
ida = "INITIATOR A"
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
    keyS = generate_key()
    #print(f'KeyS: {keyS}')
    port = 60000                    # Reserve a port for your service.
    s = socket.socket()             # Create a socket object
    s.bind(('127.0.0.1', port))            # Bind to the port
    s.listen(5)                     # Now wait for client connection.

    clientsock, addr = s.accept()  # Establish connection with client.
    clientsock.send(keyPairA.publickey().exportKey(format='PEM', passphrase=None, pkcs=1))
    msg = clientsock.recv(1024)
    pubKeyB = RSA.importKey(msg)

    print('Key distribution messages:')

    msgToSend = f'{ida}|{generate_key()}'
    cypherMsg = rsa_encrypt(msgToSend, pubKeyB)
    clientsock.send(cypherMsg)

    msg = rsa_decrypt(clientsock.recv(1024), keyPairA)
    print(f'Message 2: {msg}')
    nonceList.append(msg.decode().split('|')[-1])

    msgToSend = nonceList[-1]
    cypherMsg = rsa_encrypt(msgToSend, pubKeyB)
    clientsock.send(cypherMsg)

    msgToSend = keyS
    cypherMsg = rsa_encrypt(msgToSend, pubKeyB)
    clientsock.send(cypherMsg)

    print('**Key distribution messages end here**\n')

    thread1 = threading.Thread(target=handle_recv, args=(clientsock, keyS))
    thread1.start()

    while True:
        msgToSend = input('Enter a message: ')
        cypherMsg = des_encrypt(msgToSend, keyS)
        clientsock.send(cypherMsg)
