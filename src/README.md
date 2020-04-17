
Encrypting a message with a password
------------------------------------

```python
# Filename: fernet_example.py
from fernet_crypto import fernet_encrypt, fernet_decrypt

# We want to encrypt this text...
cleartext = "Guacamole for life"

# Create a salt and encrypted message... Use a password to encrypt
# The script will prompt for a password if none is provided.
result = fernet_encrypt(cleartext, password="abcdefg")

# Store the salt and encrypted message somewhere; both are safe to expose.

# Use the salt (above), encrypted message, and password to decrypt...
# The script will prompt for a password if none is provided.
decrypted_message = fernet_decrypt(
    b64_salt=result['b64_salt'],
    encrypted_message=result['encrypted_message'],
    password="abcdefg",
    )
```
