# SPDX-License-Identifier: GPL-3.0-or-later
"""Independent, deterministic TPAP test vectors (fake credentials only).
Requires cryptography and ecdsa. Prints JSON; never connects to a device.
"""
import base64
import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from ecdsa import NIST256p, ellipticcurve

def b64(v):
    return base64.b64encode(v).decode()

def hkdf(v, salt, info, length):
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(v)

def point(h):
    return ellipticcurve.Point.from_bytes(NIST256p.curve, bytes.fromhex(h), order=NIST256p.order)

def encode(p):
    return b"\x04" + p.x().to_bytes(32, "big") + p.y().to_bytes(32, "big")

def lp(v):
    return len(v).to_bytes(8, "little") + v

password = " fixture-pässword "
salt, ur, dr = bytes(range(16)), bytes(range(32)), bytes(range(32, 64))
x, y = 0x123456789abcdef, 0xfedcba987654321
g, order = NIST256p.generator, NIST256p.order
m = point("02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f")
n = point("03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49")
derived = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 3000, 80)
w, h = int.from_bytes(derived[:40], "big") % order, int.from_bytes(derived[40:], "big") % order
# Build server share and server-side Z,V, independently of client subtraction.
r, l = y * g + w * n, x * g + w * m
z, v = y * (l + -(w * m)), y * (h * g)
w_bytes = w.to_bytes(max(1, (w.bit_length() + 7) // 8), "big")
if len(w_bytes) % 2 and w_bytes[0] & 128:
    w_bytes = b"\0" + w_bytes
context = hashlib.sha256(b"PAKE V1" + ur + dr).digest()
transcript = b"".join(lp(v) for v in [context, b"", b"", encode(m), encode(n),
                                      encode(l), encode(r), encode(z), encode(v), w_bytes])
th = hashlib.sha256(transcript).digest()
confirm = hkdf(th, bytes(64), b"ConfirmationKeys", 64)
shared = hkdf(th, bytes(32), b"SharedKey", 32)
key = hkdf(shared, b"tp-kdf-salt-aes128-key", b"tp-kdf-info-aes128-key", 16)
nonce = hkdf(shared, b"tp-kdf-salt-aes128-iv", b"tp-kdf-info-aes128-iv", 12)
ccm = []
for length in [0, 1, 15, 16, 17, 255, 1024]:
    plaintext = bytes(i % 256 for i in range(length))
    ccm.append({"plain": b64(plaintext), "cipher": b64(AESCCM(key, tag_length=16).encrypt(nonce, plaintext, None))})
# Local test PKI: unrelated to TP-Link, no private key leaves this process.
root_key = ec.generate_private_key(ec.SECP256R1())
leaf_key = ec.generate_private_key(ec.SECP256R1())
root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Offline test CA")])
leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Offline test device")])
now = datetime.now(timezone.utc)
def cert(subject, issuer, public, signer, ca):
    return (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
            .public_key(public).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
            .sign(signer, hashes.SHA256()))
root_cert = cert(root_name, root_name, root_key.public_key(), root_key, True)
leaf_cert = cert(leaf_name, root_name, leaf_key.public_key(), root_key, False)
dac_nonce = bytes(range(32))
dac_proof = leaf_key.sign(shared + dac_nonce, ec.ECDSA(hashes.SHA256()))
print(json.dumps({
    "password": password, "userRandom": b64(ur), "x": str(x),
    "register": {"cipher_suites": 1, "encryption": "aes_128_ccm", "iterations": 3000,
                 "dev_salt": b64(salt), "dev_random": b64(dr), "dev_share": b64(encode(r)),
                 "extra_crypt": {"type": "password_shadow", "params": {"passwd_id": 4}}},
    "shared": b64(shared), "userShare": b64(encode(l)),
    "userConfirm": b64(hmac.digest(confirm[:32], encode(r), "sha256")),
    "devConfirm": b64(hmac.digest(confirm[32:], encode(l), "sha256")),
    "key": b64(key), "nonce": b64(nonce), "ccm": ccm, "pbkdf2": b64(derived),
    "scalarPoint": b64(encode(x * g)),
    "dac": {"root": root_cert.public_bytes(serialization.Encoding.PEM).decode(),
            "leaf": b64(leaf_cert.public_bytes(serialization.Encoding.DER)),
            "proof": b64(dac_proof), "nonce": b64(dac_nonce)}
}))
