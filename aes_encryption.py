from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os
import base64

def encrypt_aes(message: str, key: bytes) -> str:
    # Generate a random initialization vector (IV)
    iv = os.urandom(16)
    
    # Create a Cipher object using AES in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad the message to be AES block size compliant
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()

    # Encrypt the padded message
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    # Return the IV and ciphertext, encoded in base64 for easier storage
    return base64.b64encode(iv + ciphertext).decode()

def decrypt_aes(ciphertext: str, key: bytes) -> str:
    # Decode the base64 encoded ciphertext
    raw_data = base64.b64decode(ciphertext)
    
    # Extract the IV and actual ciphertext
    iv = raw_data[:16]
    actual_ciphertext = raw_data[16:]

    # Create a Cipher object using AES in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext
    padded_data = decryptor.update(actual_ciphertext) + decryptor.finalize()

    # Unpad the decrypted data
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    
    return data.decode()

if __name__ == "__main__":
    # Key must be either 16, 24, or 32 bytes long for AES
    key = os.urandom(32)  # Generate a random 256-bit key
    
    # Original message
    message = "This is a secret message."
    
    # Encrypt the message
    ciphertext = encrypt_aes(message, key)
    print(f"Ciphertext: {ciphertext}")

    # Decrypt the message
    decrypted_message = decrypt_aes(ciphertext, key)
    print(f"Decrypted: {decrypted_message}")
