from scapy.all import *
import time
import sys
import binascii
import crc16
import six
import base64
#import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature
#from cryptography.hazmat.primitives import serialization
import pmu, utils

class InvalidToken(Exception):
    pass

class client(object):
    def __init__(self, key, client_nonce, iv, aad, backend=default_backend()):
        self.key_pub = key
        self.key_session = None
        self.cipher = None
        self.encryptor = None
        self.decryptor = None
        self.hmac = None
        self._iv = iv
        self._client_nonce = client_nonce
        self._aad = aad
        self._backend = backend

    def cbc_decrypt(self, ciphertext, key=None):
        if key is None:
            key = self.key_pub
        cipher = Cipher(algorithms.AES(key), modes.CBC(self._iv), backend=default_backend())
        decryptor = self.cipher.decryptor()
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
        return plaintext

    def cbc_encrypt(self, plaintext, key=None):
        if key is None:
            key = self.key_pub
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext) + padder.finalize()

        self.cipher = Cipher(algorithms.AES(key), modes.CBC(self._iv), backend=self._backend)
        encryptor = self.cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        basic_parts = (b"\x80" + self._iv + ciphertext) # struct.pack(">Q", int(time.time())) +

        hm = hmac.HMAC(key, hashes.SHA256(), backend=self._backend)
        hm.update(basic_parts)
        h_mac = hm.finalize()
        payload = base64.urlsafe_b64encode(basic_parts + h_mac)
        return payload

    def verify_hmac(self, data, key=None):
        if key is None:
            key = self.key_pub
        if not data or six.indexbytes(data, 0) != 0x80:
            raise InvalidToken

        h = hmac.HMAC(key, hashes.SHA256(), backend=self._backend)
        h.update(data[:-32])
        try:
            h.verify(data[-32:])
        except InvalidSignature:
            raise InvalidToken

    def create_session(self, PDC_ID,server_nonce,MAC_PDC,MAC_PMU,cFun="AESGCM"):
        hm = hashes.Hash(hashes.SHA256(), backend=self._backend)
        hm.update(PDC_ID + self._client_nonce + server_nonce + MAC_PDC + MAC_PMU)
        self.key_session = hm.finalize()
        if cFun == "AESGCM":
            self.cipher = AESGCM(self.key_session)
        elif cFun == "ChaCha20":
            algorithm = algorithms.ChaCha20(self.key_session, self._client_nonce)
            self.cipher = Cipher(algorithm, mode=None, backend=self._backend)
            self.encryptor = self.cipher.encryptor()
            self.decryptor = self.cipher.decryptor()
        elif cFun == "CBC":
            self.cipher = Cipher(algorithms.AES(self.key_session), modes.CBC(self._iv), backend=self._backend)
            self.encryptor = self.cipher.encryptor()
            self.decryptor = self.cipher.decryptor()

        return self.key_session


    def gcm_encrypt(self, data, cFun="AESGCM"):
        if cFun == "AESGCM":
            ciphertext = self.cipher.encrypt(self._client_nonce, data, self._aad)
            basic_parts = (b"\x40" + ciphertext)
            return base64.urlsafe_b64encode(basic_parts)
        elif cFun == "ChaCha20":
            ciphertext = self.encryptor.update(data)
            basic_parts = (b"\x40" + ciphertext)
            self.hmac = hmac.HMAC(self.key_session, hashes.SHA256(), backend=self._backend)
            self.hmac.update(basic_parts)
            h_mac = self.hmac.finalize()
            payload = base64.urlsafe_b64encode(basic_parts + h_mac)
            return payload
        elif cFun == "CBC":
            ciphertext = self.encryptor.update(data)
            basic_parts = (b"\x40" + ciphertext)
            self.hmac = hmac.HMAC(self.key_session, hashes.SHA256(), backend=self._backend)
            self.hmac.update(basic_parts)
            h_mac = self.hmac.finalize()
            payload = base64.urlsafe_b64encode(basic_parts + h_mac)
            return payload

    def gcm_decryt(self, data, cFun="AESGCM", nonce=None, aad=None):
        if not data or six.indexbytes(data, 0) != 0x40:
            raise InvalidToken
        if cFun == "AESGCM":
            return self.cipher.decrypt(nonce, data, aad)
        elif cFun == "ChaCha20":
            self.hmac = hmac.HMAC(self.key_session, hashes.SHA256(), backend=self._backend)
            self.hmac.update(data[:-32])
            try:
                self.hmac.verify(data[-32:])
            except InvalidSignature:
                raise InvalidToken
            return self.decryptor.update(data[:-32])
        elif cFun == "CBC":
            self.hmac = hmac.HMAC(self.key_session, hashes.SHA256(), backend=self._backend)
            self.hmac.update(data[:-32])
            try:
                self.hmac.verify(data[-32:])
            except InvalidSignature:
                raise InvalidToken
            return self.decryptor.update(data[:-32])

#read/gen public key
# pk = os.urandom(32) #256bits public key
if __name__ == "__main__":

    with open("pk.pem", "r") as f:
            pk = f.read()

    # with open("iv.nouce", "r") as f:
    #         iv = f.read()

    MAC_PDC = "06:j0:74:u9:98:50 "
    MAC_PMU = "98:50:06:j0:74:u9"
    PDC_ID = "HTB"
    PMU_server_ip = "127.0.0.1"
    PDC_server_ip = "127.0.0.1"
    PMU_port = 8001
    PDC_port = 8002
    network_face = "lo"

    #_MAX_CLOCK_SKEW = 60
    frame_rate = 1.0/30
    #gen nonce for pmu and pdc
    client_nonce = os.urandom(16)
    iv = os.urandom(16)
    aad = os.urandom(16)
    pmu = client(pk,client_nonce,iv,aad,default_backend())
    #pmu.cipher = Cipher(algorithms.AES(pmu.key_pub), modes.CBC(pmu._iv), backend=pmu._backend)
    payload = pmu.cbc_encrypt(client_nonce + aad)
    ans = utils.packet_send(payload, src=PMU_server_ip, dst=PDC_server_ip, flag= "S",sport=PMU_port,
     dport=PDC_port, mode=sr1)
    # = sniff(iface=network_face, filter="tcp and src host " + str(PDC_server_ip) + " and dst port " + str(PMU_port), timeout = 10, count = 1)
    print("waiting for response")
    data = base64.urlsafe_b64decode(ans[0].load)
    pmu.verify_hmac(data)

    ciphertext = data[1:-32]
    plaintext = pmu.cbc_decrypt(ciphertext)
    server_nonce = plaintext[:13]

    cFun = "AESGCM"
    pkts = rdpcap("PMU.pcap")
    data = pkts[0].load

    pmu.create_session(PDC_ID,server_nonce,MAC_PDC,MAC_PMU,cFun=cFun)

    print("start sending pmu data ................")
    cnt = 0
    starttime = time.time()
    for i in range(1):
        while time.time() - starttime < 60:
            ciphertext = pmu.gcm_encrypt(data,cFun=cFun)
            cnt += 1
        print(cnt)
        utils.packet_send(ciphertext, src=PMU_server_ip, dst=PDC_server_ip, sport=PMU_port, dport=PDC_port, flag=18, mode=send)
        
        while True:
            if (time.time() - starttime) > frame_rate:
                starttime += frame_rate
                break
