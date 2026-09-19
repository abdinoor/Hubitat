"""Independent fake-credential KLAP vectors; no network or real credentials."""
import base64
import hashlib
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

def b64(value):
    return base64.b64encode(value).decode()

user, password = "fixture@example.test", " fixture-pässword "
local, remote = bytes(range(16)), bytes(range(16, 32))
vectors = []
for v2 in (False, True):
    md5 = lambda v: hashlib.md5(v).digest()
    sha1 = lambda v: hashlib.sha1(v).digest()
    sha256 = lambda v: hashlib.sha256(v).digest()
    auth = sha256(sha1(user.encode()) + sha1(password.encode())) if v2 else md5(md5(user.encode()) + md5(password.encode()))
    common = local + remote + auth
    key, iv, sig = sha256(b"lsk" + common)[:16], sha256(b"iv" + common), sha256(b"ldk" + common)[:28]
    initial = int.from_bytes(iv[-4:], "big", signed=True)
    seq = initial + 1
    seq_bytes = seq.to_bytes(4, "big", signed=True)
    plain = b'{"error_code":0,"result":{"device_on":true,"brightness":62}}'
    padder = PKCS7(128).padder()
    padded = padder.update(plain) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv[:12] + seq_bytes)).encryptor()
    cipher = enc.update(padded) + enc.finalize()
    vectors.append(dict(v2=v2, auth=b64(auth), key=b64(key), iv=b64(iv[:12]), sig=b64(sig), initial=initial,
        handshake1=b64(sha256(local + remote + auth) if v2 else sha256(local + auth)),
        handshake2=b64(sha256(remote + local + auth) if v2 else sha256(remote + auth)),
        plaintext=b64(plain), encrypted=b64(sha256(sig + seq_bytes + cipher) + cipher)))
print(json.dumps(dict(user=user, password=password, local=b64(local), remote=b64(remote), vectors=vectors)))
