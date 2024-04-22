from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from hashlib import sha256

key_length = 4096
user_pin = "2134"
cipher_block_size = AES.block_size
cipher_mode = AES.MODE_CBC

rng = get_random_bytes

key = RSA.generate(key_length, rng)
private_key = key.export_key()
public_key = key.publickey().export_key()

pin_hash = sha256(user_pin.encode()).digest()
cipher = AES.new(pin_hash, mode=cipher_mode)
encrypted_private_key = cipher.encrypt(pad(private_key, cipher_block_size))

print('Public key')
with open('../keys/public_key.key', 'wb') as file:
    file.write(public_key)

# Save the encrypted private key and encrypted AES key
print('Encrypted private key')
with open('../keys/private_key.key', 'wb') as file:
    file.write(encrypted_private_key)
