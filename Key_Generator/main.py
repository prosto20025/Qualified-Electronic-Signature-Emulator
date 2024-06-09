import hashlib

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from hashlib import sha256

key_length = 4096
user_pin = "2134"
cipher_block_size = AES.block_size
cipher_mode = AES.MODE_CBC


key = RSA.generate(key_length)
private_key_pem = key.export_key()
public_key_pem = key.publickey().export_key()

pin_hashed = hashlib.sha3_256()
pin_hashed.update(user_pin.encode())
pin_hashed = pin_hashed.digest()

cipher = AES.new(pin_hashed, mode=cipher_mode)
iv = cipher.iv

encrypted_private_key = iv + cipher.encrypt(pad(private_key_pem, cipher_block_size))

print('Public key')
with open('../keys/public_key.pem', 'wb') as file:
    file.write(public_key_pem)

print('Encrypted private key')
with open('../keys/private_key.pem', 'wb') as file:
    file.write(encrypted_private_key)
