
from getpass import getpass
import base64
import sys
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
        if sys.version_info>=(3, 0, 0):
            passwd = bytes(getpass(), encoding=encoding)
        else:
            passwd = bytes(getpass())
    else:
        if sys.version_info>=(3, 0, 0):
            passwd = bytes(password, encoding=encoding)
        else:
            passwd = password


    salt = os.urandom(salt_size_bytes) # salt_size_bytes should be > 80 bytes
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF_ITERATIONS,
        backend=default_backend()
    )
    #key = base64.urlsafe_b64encode(kdf.derive(bytes(passwd, encoding='utf-8')))
    key = base64.urlsafe_b64encode(kdf.derive(passwd))
    ff = Fernet(key)

    if sys.version_info>=(3, 0, 0):
        encrypted_message = ff.encrypt(bytes(cleartext_message,
            encoding=encoding))
    else:
        encrypted_message = ff.encrypt(bytes(cleartext_message))
        encrypted_message = bytes(encrypted_message)

    # return strings with the requested encoding
    return {'b64_salt': base64.urlsafe_b64encode(salt).decode(encoding),
        'encrypted_message': encrypted_message.decode(encoding)}

def fernet_decrypt(b64_salt="", encrypted_message="", password="",
    encoding='utf=8'):
    assert b64_salt!=""
    assert encrypted_message!=""

    if password=="":
        if sys.version_info>=(3, 0, 0):
            passwd = bytes(getpass(), encoding=encoding)
        else:
            passwd = getpass()
    else:
        if sys.version_info>=(3, 0, 0):
            passwd = bytes(password, encoding=encoding)
        else:
            passwd = password

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=base64.urlsafe_b64decode(str(b64_salt)),
        iterations=PBKDF_ITERATIONS,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(passwd))
    ff = Fernet(key)
    if sys.version_info>=(3, 0, 0):
        decrypted_message = ff.decrypt(bytes(encrypted_message,
            encoding=encoding)).decode(encoding) # return a string
    else:
        decrypted_message = ff.decrypt(bytes(encrypted_message)).decode(
            encoding) # return a string

    return decrypted_message

if __name__=="__main__":
    encrypted = fernet_encrypt('abc123')
    print("ENCRYPTED "+str(encrypted))
    decrypt = fernet_decrypt(encrypted['b64_salt'],
        encrypted['encrypted_message'])
    print("DECRYPTED "+decrypt)
