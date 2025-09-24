import base64
import json
from hashlib import pbkdf2_hmac
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from config import Config

# --- MODIFICATION: The key derivation logic has been moved up ---
# This ensures 'derived_key' is created before it's used by the functions below.

# This derives a strong, 32-byte (256-bit) encryption key from your user key and salt.
derived_key = pbkdf2_hmac(
    'sha256',
    Config.ENCRYPTION_USER_KEY.encode('utf-8'),
    Config.ENCRYPTION_SALT.encode('utf-8'),
    100000,
    dklen=32  # Get a 32-byte key for AES-256
)
# --- END MODIFICATION ---


def encrypt_data(data_dict):
    """
    Encrypts a dictionary using AES-GCM, providing confidentiality and integrity.
    Returns a base64-encoded string containing nonce, tag, and ciphertext.
    """
    try:
        json_string = json.dumps(data_dict, separators=(',', ':'))
        header = b'Luminous Encrypted Data' # Optional header for context
        plaintext = json_string.encode('utf-8')

        cipher = AES.new(derived_key, AES.MODE_GCM)
        cipher.update(header)
        
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        
        combined_data = cipher.nonce + tag + ciphertext
        
        return base64.b64encode(combined_data).decode('utf-8')
    except Exception as e:
        print(f"Encryption failed: {e}")
        return None

def decrypt_data(encrypted_b64_string):
    """
    Decrypts a base64-encoded string that was encrypted with AES-GCM.
    Verifies the integrity of the data before returning the dictionary.
    """
    try:
        combined_data = base64.b64decode(encrypted_b64_string)
        header = b'Luminous Encrypted Data'

        nonce = combined_data[:16]
        tag = combined_data[16:32]
        ciphertext = combined_data[32:]

        cipher = AES.new(derived_key, AES.MODE_GCM, nonce=nonce)
        cipher.update(header)
        
        decrypted_bytes = cipher.decrypt_and_verify(ciphertext, tag)
        
        return json.loads(decrypted_bytes.decode('utf-8'))
    except (ValueError, KeyError, IndexError, json.JSONDecodeError):
        return None
