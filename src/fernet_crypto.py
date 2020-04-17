
from getpass import getpass
import base64
import os

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

PBKDF_ITERATIONS = 1000000

def fernet_encrypt(cleartext_message="", password="", encoding='utf-8',
    salt_size_bytes=128): 
    # Get the password we use to encrypt the cleartext_message
    if password=="":
        passwd = getpass()
    else:
        passwd = bytes(password, encoding=encoding)

    salt = os.urandom(salt_size_bytes) # salt_size_bytes should be > 80 bytes
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF_ITERATIONS,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(passwd))
    ff = Fernet(key)
    encrypted_message = ff.encrypt(bytes(cleartext_message, encoding=encoding))

    return {'b64_salt': base64.urlsafe_b64encode(salt),
        'encrypted_message': encrypted_message}

def fernet_decrypt(b64_salt="", encrypted_message="", password="",
    encoding='utf=8'):
    assert b64_salt!=""
    assert encrypted_message!=""
    if password=="":
        passwd = getpass()
    else:
        passwd = bytes(password, encoding=encoding)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=base64.urlsafe_b64decode(b64_salt),
        iterations=PBKDF_ITERATIONS,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(passwd))
    ff = Fernet(key)
    return ff.decrypt(encrypted_message)
