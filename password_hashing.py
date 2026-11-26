import pwdlib

password_hasher = pwdlib.PasswordHash.recommended()


def hash_password(password: str) -> str:
    """Hash a plain-text password."""
    return password_hasher.hash(password)


def verify_password(password_to_verify: str, ground_truth_password_hash: str) -> bool:
    """Check a plain-text password against a stored hash."""
    return password_hasher.verify(password_to_verify, ground_truth_password_hash)
