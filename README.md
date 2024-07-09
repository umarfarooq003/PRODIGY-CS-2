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
