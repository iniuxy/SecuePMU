import os
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
data = b"a secret message"
aad = b"authenticated but unencrypted data" #authentication key
uad = b"authenticated but unencrypted"
key = AESCCM.generate_key(bit_length=128)
aesccm = AESCCM(key)
nonce = os.urandom(13)
ct = aesccm.encrypt(nonce, data, aad)
print(ct)
print(aesccm.decrypt(nonce, ct, aad))


# #https://cryptography.io/en/latest/hazmat/primitives/mac/hmac/
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives import hashes, hmac
# h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
# h.update(b"message to hash")
# h.finalize()
# h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
# h.update(b"message to hash")
# h.verify(b"an incorrect signature")
#
# #https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/
# import os
# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# from cryptography.hazmat.backends import default_backend
# backend = default_backend()
# key = os.urandom(32)
# iv = os.urandom(16)
# cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
# encryptor = cipher.encryptor()
# ct = encryptor.update(b"a secret message") + encryptor.finalize()
# decryptor = cipher.decryptor()
# decryptor.update(ct) + decryptor.finalize()
#
# binascii.hexlify(a)
# binascii.unhexlify(_)
#
# #https://cryptography.io/en/latest/hazmat/primitives/cryptographic-hashes/
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
digest.update(b"abc")
digest.update(b"123")
digest.finalize()







from scapy.all import *
import time
import sys
import binascii
import crc16
from datetime import datetime as dt
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
import pmu, utils

#read/gen public key
iv = os.urandom(16)
# pk = os.urandom(32) #256bits public key

with open("pk.pem", "r") as f:
        pk = f.read()

with open("iv.nouce", "r") as f:
        iv = f.read()

MAC_PDC = "06:j0:74:u9:98:50 "
MAC_PMU = "98:50:06:j0:74:u9"
PDC_ID = "HTB"

#gen nonce for pmu and pdc
client_nonce = os.urandom(13)
server_nonce = os.urandom(13)
cipher = Cipher(algorithms.AES(pk), modes.CBC(iv), backend=default_backend())
encryptor = cipher.encryptor()
ct = encryptor.update(en_aad) + encryptor.finalize()

hm = hmac.HMAC(pk, hashes.SHA256(), backend=default_backend())
hm.update(client_nonce + server_nonce)
h_mac = hm.finalize()

hm = hmac.HMAC(pk, hashes.SHA256(), backend=default_backend())
hm.update(client_nonce + server_nonce)
hm.verify(h_mac)

h = hashes.Hash(hashes.SHA256(), backend=default_backend())
h.update(PDC_ID + client_nonce + server_nonce + MAC_PDC + MAC_PMU)
sk = h.finalize()

en_aad = os.urandom(16)
ct = encryptor.update(en_aad) + encryptor.finalize()

decryptor = cipher.decryptor()
tmp = decryptor.update(ct) + decryptor.finalize()

nonce = tmp[0:13]
aad = tmp[13:]

pkts = rdpcap("PMU.pcap")
data = pkts[0].load
print(data)
aesccm = AESCCM(sk)
ct = aesccm.encrypt(client_nonce, data, aad)
hm = hmac.HMAC(pk, hashes.SHA256(), backend=default_backend())
# hm.update(ct)

del pkts[0][Raw]
packet = pkts[0]/Raw("".join(ct))
data = aesccm.decrypt(client_nonce, packet.load, aad)
print(data)







 This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.
from __future__ import absolute_import, division, print_function
import base64
import binascii
import os
import struct
import time
import six
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
class InvalidToken(Exception):
    pass
_MAX_CLOCK_SKEW = 60
class Fernet(object):
    def __init__(self, key, backend=None):
        if backend is None:
            backend = default_backend()
        key = base64.urlsafe_b64decode(key)
        if len(key) != 32:
            raise ValueError(
                "Fernet key must be 32 url-safe base64-encoded bytes."
            )
        self._signing_key = key[:16]
        self._encryption_key = key[16:]
        self._backend = backend
    @classmethod
    def generate_key(cls):
        return base64.urlsafe_b64encode(os.urandom(32))
    def encrypt(self, data):
        current_time = int(time.time())
        iv = os.urandom(16)
        return self._encrypt_from_parts(data, current_time, iv)
    def _encrypt_from_parts(self, data, current_time, iv):
        if not isinstance(data, bytes):
            raise TypeError("data must be bytes.")
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        encryptor = Cipher(
            algorithms.AES(self._encryption_key), modes.CBC(iv), self._backend
        ).encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        basic_parts = (
            b"\x80" + struct.pack(">Q", current_time) + iv + ciphertext
        )
        h = HMAC(self._signing_key, hashes.SHA256(), backend=self._backend)
        h.update(basic_parts)
        hmac = h.finalize()
        return base64.urlsafe_b64encode(basic_parts + hmac)
    def decrypt(self, token, ttl=None):
        if not isinstance(token, bytes):
            raise TypeError("token must be bytes.")
        current_time = int(time.time())
        try:
            data = base64.urlsafe_b64decode(token)
        except (TypeError, binascii.Error):
            raise InvalidToken
        if not data or six.indexbytes(data, 0) != 0x80:
            raise InvalidToken
        try:
            timestamp, = struct.unpack(">Q", data[1:9])
        except struct.error:
            raise InvalidToken
        if ttl is not None:
            if timestamp + ttl < current_time:
                raise InvalidToken
        if current_time + _MAX_CLOCK_SKEW < timestamp:
            raise InvalidToken
        h = HMAC(self._signing_key, hashes.SHA256(), backend=self._backend)
        h.update(data[:-32])
        try:
            h.verify(data[-32:])
        except InvalidSignature:
            raise InvalidToken
        iv = data[9:25]
        ciphertext = data[25:-32]
        decryptor = Cipher(
            algorithms.AES(self._encryption_key), modes.CBC(iv), self._backend
        ).decryptor()
        plaintext_padded = decryptor.update(ciphertext)
        try:
            plaintext_padded += decryptor.finalize()
        except ValueError:
            raise InvalidToken
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        unpadded = unpadder.update(plaintext_padded)
        try:
            unpadded += unpadder.finalize()
        except ValueError:
            raise InvalidToken
        return unpadded
class MultiFernet(object):
    def __init__(self, fernets):
        fernets = list(fernets)
        if not fernets:
            raise ValueError(
                "MultiFernet requires at least one Fernet instance"
            )
        self._fernets = fernets
    def encrypt(self, msg):
        return self._fernets[0].encrypt(msg)
    def decrypt(self, msg, ttl=None):
        for f in self._fernets:
            try:
                return f.decrypt(msg, ttl)
            except InvalidToken:
                pass
        raise InvalidToken
