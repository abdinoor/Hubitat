"""Independent Tuya 3.3 test vectors. Fake credentials; no network access."""
import json
import struct
import zlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

key = b"0123456789abcdef"
version = b"3.3" + bytes(12)
def encrypt(text):
    pad = PKCS7(128).padder()
    data = pad.update(text.encode()) + pad.finalize()
    cipher = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return cipher.update(data) + cipher.finalize()

def pack(seq, command, body):
    header = struct.pack(">4I", 0x55AA, seq, command, len(body) + 8)
    data = header + body
    return (data + struct.pack(">2I", zlib.crc32(data), 0xAA55)).hex()

plain = '{"dps":{"1":true,"2":620}}'
ciphertext = encrypt(plain)
print(json.dumps(dict(key=key.decode(), plaintext=plain, cipher=ciphertext.hex(),
    query=pack(41, 10, ciphertext), control=pack(42, 7, version + ciphertext),
    response=pack(41, 10, bytes(4) + ciphertext),
    status=pack(0, 8, bytes(4) + version + ciphertext),
    ack=pack(42, 7, bytes(4)), rejected=pack(42, 7, struct.pack(">I", 1)))))
