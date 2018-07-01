#!/usr/bin/env python3

"""
Utility to dump neo-gui or neo-cli db3 (sqlite) wallet keys
Author: hal0x2328
License: MIT
Install: pip3 install sqlite3 pycrypto neocore
"""

import sqlite3
import hashlib
from builtins import input 
import sys
from Crypto.Cipher import AES
from neocore.KeyPair import KeyPair

def to_aes_key(password):
    password_hash = hashlib.sha256(password.encode('utf-8')).digest()
    return hashlib.sha256(password_hash).digest()

if len(sys.argv) != 2:
    print("Usage: {} <neo-gui/neo-cli wallet db3 file>".format(sys.argv[0]))
    sys.exit()

filename = sys.argv[1]

password = input("Password: ")

conn = sqlite3.connect(filename)
c = conn.cursor()

c.execute("SELECT name, value from Key")
for tup in c.fetchall():
    name = tup[0]
    value = tup[1]
    if name == 'PasswordHash':
        PasswordHash = value
    elif name == 'MasterKey':
        MasterKey = value
    elif name == 'IV':
        IV = value

passwordKey = to_aes_key(password)

if  hashlib.sha256(passwordKey).digest() != PasswordHash:
        print("Wrong password")
else:
    aes = AES.new(passwordKey, AES.MODE_CBC, IV)
    mk = aes.decrypt(MasterKey)

    c.execute("SELECT PublicKeyHash, PrivateKeyEncrypted from Account")

    for tup in c.fetchall():
        PublicKeyHash = tup[0]
        PrivateKeyEncrypted = tup[1]
        aes = AES.new(mk, AES.MODE_CBC, IV)
        decrypted = aes.decrypt(PrivateKeyEncrypted)
        kp = KeyPair(decrypted)
        print("{} : {}".format(kp.GetAddress(), kp.Export()))

conn.close()
