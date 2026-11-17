
"""
Week 3 — FIX the misuse here.
pip install argon2-cffi pycryptodome
"""
import os
import secrets
from argon2 import PasswordHasher
from Crypto.Cipher import AES

ph = PasswordHasher()


def store_password(pw: str) -> str:
    # FIX: Argon2id with automatic salt
    return ph.hash(pw)


def verify_password(hash_: str, pw: str) -> bool:
    # FIX: Verify the Argon2id password hash
    try:
        return ph.verify(hash_, pw)
    except Exception:
        return False


def encrypt_gcm(data: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    # FIX: AES-GCM with a random 12-byte nonce
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24, or 32 bytes")

    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    return nonce, ciphertext, tag


def reset_token() -> str:
    # FIX: Cryptographically secure random token
    return secrets.token_urlsafe(16)


if __name__ == "__main__":
    # FIX: Load encryption key from environment
    key_hex = os.environ.get("ENC_KEY_HEX")

    if not key_hex:
        raise RuntimeError("Please set ENC_KEY_HEX environment variable")

    key = bytes.fromhex(key_hex)

    if len(key) != 32:
        raise ValueError("ENC_KEY_HEX must contain a 32-byte AES key")

    h = store_password("password123")

    print("argon2 ok:", verify_password(h, "password123"))

    nonce, ciphertext, tag = encrypt_gcm(b"secret", key)
    print("gcm encryption successful:", len(nonce), len(ciphertext), len(tag))

    print("token:", reset_token())
