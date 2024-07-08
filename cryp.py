import argparse
from cryptography.fernet import Fernet

# Generate a random key (store this securely!)
key = Fernet.generate_key()
cipher_suite = Fernet(key)

def encrypt_password(password):
    return cipher_suite.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password):
    return cipher_suite.decrypt(encrypted_password.encode()).decode()

# Parse command-line arguments
parser = argparse.ArgumentParser(description="Encrypt and decrypt a password")
parser.add_argument("password", help="Password to encrypt")
args = parser.parse_args()

stored_password = encrypt_password(args.password)
print(f"Encrypted password: {stored_password}")

retrieved_password = decrypt_password(stored_password)
print(f"Retrieved password: {retrieved_password}")
