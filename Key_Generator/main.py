from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from hashlib import sha256

# Generate RSA key pair
key = RSA.generate(4096)
private_key = key.export_key()
public_key = key.publickey().export_key()

# User A's PIN number
pin = "2134"

# Hash the PIN using SHA-256
pin_hash = sha256(pin.encode()).digest()

# Encrypt the private key with AES using the hashed PIN as the key
cipher = AES.new(pin_hash, AES.MODE_EAX)
ciphertext = cipher.encrypt(private_key)

# Display the public key
print('Public key:')
print(public_key.decode())

# Wrap the AES key with the user's public RSA key
rsa_key = RSA.import_key(public_key)
cipher_rsa = PKCS1_OAEP.new(rsa_key)
encrypted_aes_key = cipher_rsa.encrypt(pin_hash)

# Store the encrypted private key and encrypted AES key on the pendrive
encrypted_private_key = ciphertext + encrypted_aes_key

# Display the encrypted private key and encrypted AES key (for demonstration purposes)
print('Encrypted private key:')
print(encrypted_private_key.hex())
