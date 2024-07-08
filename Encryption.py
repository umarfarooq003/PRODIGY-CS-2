from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64
import os

def generate_key(password):
    salt = b"random_salt"  # Store this securely!
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_file(file_path, password):
    key = generate_key(password)
    cipher_suite = Fernet(key)

    try:
        with open(file_path, "rb+") as file:  # Open file in read/write mode
            plaintext = file.read()
            encrypted_data = cipher_suite.encrypt(plaintext)
            file.seek(0)  # Move pointer to the beginning of the file
            file.write(encrypted_data)  # Overwrite with encrypted data
            file.truncate(len(encrypted_data))  # Truncate to the length of encrypted data

        # Rename the file to have .enc extension
        encrypted_file_path = file_path + ".enc"
        os.rename(file_path, encrypted_file_path)

        print(f"Encryption successful! File '{file_path}' encrypted and renamed to '{encrypted_file_path}'.")

    except FileNotFoundError:
        print(f"File not found: {file_path}")
    except Exception as e:
        print(f"Error encrypting file: {e}")

def decrypt_file(encrypted_file_path, password):
    key = generate_key(password)
    cipher_suite = Fernet(key)

    try:
        with open(encrypted_file_path, "rb+") as file:  # Open file in read/write mode
            encrypted_data = file.read()
            decrypted_data = cipher_suite.decrypt(encrypted_data)
            file.seek(0)  # Move pointer to the beginning of the file
            file.write(decrypted_data)  # Overwrite with decrypted data
            file.truncate(len(decrypted_data))  # Truncate to the length of decrypted data

        # Remove the .enc extension from the filename
        decrypted_file_path = encrypted_file_path[:-4]
        os.rename(encrypted_file_path, decrypted_file_path)

        print(f"Decryption successful! File '{encrypted_file_path}' decrypted and renamed to '{decrypted_file_path}'.")

    except FileNotFoundError:
        print(f"Encrypted file not found: {encrypted_file_path}")
    except Exception as e:
        print(f"Error decrypting file: {e}")

# Function to handle user input for encryption or decryption
def main():
    while True:
        print("Menu:")
        print("1. Encryption")
        print("2. Decryption")
        print("3. Exit")
        choice = input("Enter your choice (1/2/3): ")

        if choice == "1":
            file_path = input("Enter the file path to encrypt: ").strip('"')  # Remove quotes from the file path if present
            password = input("Enter the password for encryption: ")
            encrypt_file(file_path, password)
        elif choice == "2":
            encrypted_file_path = input("Enter the path to the encrypted file: ").strip('"')  # Remove quotes from the file path if present
            password = input("Enter the password for decryption: ")
            decrypt_file(encrypted_file_path, password)
        elif choice == "3":
            print("Exiting program...")
            break
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")

if __name__ == "__main__":
    main()
