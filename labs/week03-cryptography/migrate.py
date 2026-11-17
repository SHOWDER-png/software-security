
"""
Week 3 — Task 5: move legacy MD5 password records to argon2id, one login at a time.
Fill in the TODO in login(), then run this file again: every check below should say PASS.
"""
import hashlib, hmac
from argon2 import PasswordHasher

ph = PasswordHasher()

# A tiny user table.
db = {
    "alice": hashlib.md5(b"password123").hexdigest(),
    "bob": ph.hash("correct horse battery staple"),
}

def is_legacy_md5(record: str) -> bool:
    return len(record) == 32 and all(c in "0123456789abcdef" for c in record)

def login(user: str, pw: str) -> bool:
    record = db.get(user)
    if record is None:
        return False

    if is_legacy_md5(record):
        # Verify the password against the legacy MD5 record.
        candidate = hashlib.md5(pw.encode()).hexdigest()

        if not hmac.compare_digest(candidate, record):
            return False

        # Upgrade the password record to Argon2id after successful login.
        db[user] = ph.hash(pw)
        return True

    try:
        return ph.verify(record, pw)
    except Exception:
        return False

if __name__ == "__main__":
    print("alice before:", db["alice"])
    checks = [
        ("a wrong password is refused", not login("alice", "wrong")),
        ("a failed login leaves the record alone", is_legacy_md5(db["alice"])),
        ("the right password is accepted", login("alice", "password123")),
        ("alice's record is now argon2id", db["alice"].startswith("$argon2id$")),
        ("her next login goes through argon2id", login("alice", "password123") and not is_legacy_md5(db["alice"])),
        ("bob (already argon2id) still logs in", login("bob", "correct horse battery staple")),
    ]

    print("alice after: ", db["alice"])
    for name, ok in checks:
        print("PASS" if ok else "FAIL", "-", name)

    print("ALL PASS" if all(ok for _, ok in checks) else "Not done yet: fill in the TODO in login().")
