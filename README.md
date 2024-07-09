# Security and Encryption Tools

This project contains multiple security and encryption tools, including a password complexity checker, password encryption and decryption scripts, file encryption and decryption scripts, and a port scanner.

## Tools

### 1. Password Complexity Checker

A web-based tool that evaluates the strength of a password based on specific criteria.

#### Features
- Checks for at least 8 characters.
- Ensures the presence of at least one uppercase letter.
- Ensures the presence of at least one lowercase letter.
- Ensures the presence of at least one number.
- Ensures the presence of at least one special character.
- Provides real-time feedback.

#### Technologies
- HTML
- CSS
- JavaScript

#### Usage
1. Open the `index.html` file in a web browser.
2. Enter a password to see the feedback.

#### Files
- `index.html`
- `password.css`
- `passwordChecker.js`

### 2. Password Encryption and Decryption

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
```bash
- python password_script.py <your_password> 

#### File
- `password_script.py`

### 3. File Encryption and Decryption
Python script to encrypt and decrypt files using a password-derived key.
#### Features
- Encrypts a file and renames it with a `.enc` extension.
- Decrypts an encrypted file and restores its original name.

#### Dependencies
- `cryptography`
- `os`
#### Usage
Run the script and follow the menu instructions:
(```python file_encrypt_decrypt.py```)

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
(```python port_scanner.py```)
### File
- `port_scanner.py`
#### Installation
1. Clone the repository
(```git clone <repository_url>```)
2. Navigate to the project directory:
(```cd <repository_name>```)
3. Install the required Python Languages:
(```pip install cryptography```)
### License
This project is open source and available under the MIT License.

### Author
- `Umar Farooq`
