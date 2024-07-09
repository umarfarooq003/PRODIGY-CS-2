# Security and Encryption Tools

This project contains multiple security and encryption tools, including a password complexity checker, password encryption and decryption scripts, file encryption and decryption scripts, and a port scanner.

## Tools


### 1. Password Encryption and Decryption

Python script to encrypt and decrypt passwords using Fernet symmetric encryption.

#### Features
- Generates a random key for encryption.
- Encrypts the given password.
- Decrypts the stored password.

#### Dependencies
- `cryptography`
- `argparse`

#### Usage
Run the script from the command line with a password as an argument:

``` bash
  python password_script.py <your_password>
```
#### File
- `password_script.py`
  
```python
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
```

### 2. File Encryption and Decryption
Python script to encrypt and decrypt files using a password-derived key.
#### Features
- Encrypts a file and renames it with a `.enc` extension.
- Decrypts an encrypted file and restores its original name.

#### Dependencies
- `cryptography`
- `os`
#### Usage
Run the script and follow the menu instructions:
``` bash
 python file_encrypt_decrypt.py
```

#### File
- `file_encrypt_decrypt.py`

   ``` python
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
        ```
### Port Scanner
Python script to scan a range of ports on a target host to determine which ports are open.
#### Features
- Scans a specified range of ports.
- Identifies and prints open ports.
#### Dependencies
- `socket`
#### Usage
Run the script and provide the target host and port range:
""" python port_scanner.py """
### File
- `port_scanner.py`
  
  ``` python
 import socket
def scan_ports(target_host, port_range):
    for port in range(*port_range):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                s.connect((target_host, port))
                print(f"Port {port} is open")
        except (socket.timeout, ConnectionRefusedError):
            pass

# Get input from the user
target_host = input("Enter the target host: ")
port_range = input("Enter the port range (e.g., 1-1024): ").split('-')
port_range = (int(port_range[0]), int(port_range[1]) + 1)
scan_ports(target_host, port_range)
     ```
#### Installation
1. Clone the repository
``` bash
git clone <repository_url>
```
2. Navigate to the project directory:
``` bash
cd <repository_name>
```
3. Install the required Python Languages:
  ``` bash
   pip install cryptography
  ```
### License
This project is open source and available under the MIT License.

### Author
- `Umar Farooq`
