from scapy.all import *
import time
import sys
import binascii
import crc16
#import struct
import six
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature
import pmu, utils

class InvalidToken(Exception):
    pass


class server(object):
    def __init__(self, key, server_nonce, backend=default_backend()):
        self.key_pub = key
        self.key_session = None
        self.hmac = None
        self.cipher = None
        self.decryptor = None
        self._iv = None
        self._server_nonce = server_nonce
        self._backend = backend

    def cbc_decrypt(self, ciphertext, key=None):
        if key is None:
            key = self.key_pub
        self.cipher = Cipher(algorithms.AES(key), modes.CBC(self._iv), backend=self._backend)
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

    def cbc_encrypt(self, plaintext, key=None):
        if key is None:
            key = self.key_pub
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        self.cipher = Cipher(algorithms.AES(key), modes.CBC(self._iv), backend=self._backend)
        encryptor = self.cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        basic_parts = (b"\x80" + ciphertext) # struct.pack(">Q", int(time.time())) +

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

        # try:
        #     timestamp, = struct.unpack(">Q", data[1:9])
        # except struct.error:
        #     raise InvalidToken
        #
        # if timestamp + ttl < int(time.time()):
        #     raise InvalidToken

        h = hmac.HMAC(key, hashes.SHA256(), backend=self._backend)
        h.update(data[:-32])
        try:
            h.verify(data[-32:])
        except InvalidSignature:
            raise InvalidToken

    def create_session(self, PDC_ID,client_nonce,MAC_PDC,MAC_PMU,cFun="AESGCM"):
        h = hashes.Hash(hashes.SHA256(), backend=self._backend)
        h.update(PDC_ID + client_nonce + self._server_nonce + MAC_PDC + MAC_PMU)
        self.key_session = h.finalize()
        if cFun == "AESGCM":
            self.cipher = AESGCM(self.key_session)
        elif cFun == "ChaCha20":
            algorithm = algorithms.ChaCha20(self.key_session,client_nonce)
            self.cipher = Cipher(algorithm, mode=None, backend=self._backend)
            self.decryptor = self.cipher.decryptor()
        elif cFun == "CBC":
            self.cipher = Cipher(algorithms.AES(self.key_session), modes.CBC(self._iv), backend=self._backend)
            self.decryptor = self.cipher.decryptor()

        return self.key_session

    def gcm_decryt(self, data, cFun="AESGCM", nonce=None, aad=None):
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


if __name__ == "__main__":
    with open("pk.pem", "r") as f:
            pk = f.read()

    MAC_PDC = "06:j0:74:u9:98:50 "
    MAC_PMU = "98:50:06:j0:74:u9"
    PDC_ID = "HTB"
    PMU_server_ip = "127.0.0.1"
    PDC_server_ip = "127.0.0.1"
    PMU_port = 8001
    PDC_port = 8002
    cnonce_len = 16
    network_face = "lo"
    #_MAX_CLOCK_SKEW = 60

    server_nonce = os.urandom(13)
    pdc = server(pk, server_nonce, default_backend())
    print("waiting for client")
    ans = sniff(iface=network_face, filter="tcp and src host " + str(PMU_server_ip) + " and dst port " + str(PDC_port), timeout = 10, count = 1)
    data = base64.urlsafe_b64decode(ans[0].load)
    pdc.verify_hmac(data)

    pdc._iv = data[1:17]
    ciphertext = data[17:-32]
    plaintext = pdc.cbc_decrypt(ciphertext)
    client_nonce = plaintext[:cnonce_len]
    aad = plaintext[cnonce_len:]
    payload = pdc.cbc_encrypt(pdc._server_nonce)
    utils.packet_send(payload, src=PDC_server_ip, dst=PMU_server_ip, sport=PDC_port,
     dport=PMU_port, flag="A", mode=send)

    cFun="CBC"
    print("generating session key")
    pdc.create_session(PDC_ID,client_nonce,MAC_PDC,MAC_PMU,cFun=cFun)
    cnt = 0
    print("waiting pmu data ................")
    while True:
        ans = sniff(iface=network_face, filter="tcp and src host " + str(PMU_server_ip) + " and dst port " + str(PDC_port), timeout = 10, count = 1)
        data = base64.urlsafe_b64decode(ans[0].load)
        if not data or six.indexbytes(data, 0) != 0x40:
            raise InvalidToken
        # pdc.verify_hmac(data,key=pdc.key_session)
        # ciphertext = data[1:-32]
        # pmu_data = pdc.cbc_decrypt(ciphertext,key=pmu.key_session)
        pmu_data = pdc.gcm_decryt(data,cFun=cFun,nonce=client_nonce,aad=aad)
        cnt += 1
        print("Succussfully received " + str(cnt) + " pmu data")