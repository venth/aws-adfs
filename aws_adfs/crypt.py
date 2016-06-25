import base64

from Crypto.PublicKey import RSA
from Crypto.Random.random import StrongRandom


def load_key(key_file):
    try:
        content = key_file.read()
    finally:
        key_file.close()

    return RSA.importKey(content)


def encrypt(text, pub_key):
    encrypted_text, = pub_key.encrypt(text, StrongRandom().randint(0, 100000))
    return base64.b64encode(encrypted_text)


def decrypt(encrypted, priv_key):
    return priv_key.decrypt(base64.b64decode(encrypted))
