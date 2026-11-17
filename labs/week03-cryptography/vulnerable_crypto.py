import os
import secrets
from argon2 import PasswordHasher
from Crypto.Cipher import AES

ph = PasswordHasher()  # Argon2id, random salt per hash

def store_password(pw: str) -> str:
    return ph.hash(pw)

def verify_password(hash_: str, pw: str) -> bool:
    try:
        return ph.verify(hash_, pw)
    except Exception:
        return False

def encrypt_gcm(data: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24, or 32 bytes")
    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return nonce, ciphertext, tag

def reset_token() -> str:
    return secrets.token_urlsafe(16)
