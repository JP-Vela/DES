# DES and Triple DES Implementation in Python

This repository contains an implementation of the **Data Encryption Standard (DES)** and **Triple DES (T_DES)** encryption algorithms in Python. It supports different encryption modes including **ECB (Electronic Codebook), CBC (Cipher Block Chaining), and OFB (Output Feedback).**

## Features
- **DES Encryption & Decryption**
- **Triple DES (T_DES) Encryption & Decryption**
- **Supports ECB, CBC, and OFB Modes**
- **Padding and Key Scheduling Implementation**
- **Customizable Initialization Vector (IV)** for CBC and OFB modes

## Installation
Clone the repository:
```bash
git clone https://github.com/JP-Vela/DES.git
cd DES
```

## Usage

### DES Encryption & Decryption
```python
from cui_des import DES

key = b'secret_k'  # 8-byte key
data = b'hello123'

# Encrypt
des = DES(mode='ECB', key=key)
ciphertext = des.encrypt(data)

# Decrypt
plaintext = des.decrypt(ciphertext)
print(f"Decrypted: {plaintext}")
```

### Triple DES (T_DES) Encryption & Decryption
```python
from cui_des import T_DES

key = b'24-byte-super-secure-key'  # 24-byte key for Triple DES
data = b'hello there'

# Encrypt
tdes = T_DES(mode='ECB', key=key)
ciphertext = tdes.encrypt(data)

# Decrypt
plaintext = tdes.decrypt(ciphertext)
print(f"Decrypted: {plaintext}")
```

### Using CBC Mode with IV
```python
key = b'24-byte-super-secure-key'
iv = b'8-byteIV'  # Initialization Vector
data = b'confidential'

tdes = T_DES(mode='CBC', key=key)
ciphertext = tdes.encrypt(data, iv=iv)
plaintext = tdes.decrypt(ciphertext, iv=iv)

print(f"Decrypted: {plaintext}")
```

## Notes
- **Key Lengths:**
  - DES requires an **8-byte (64-bit) key**.
  - Triple DES (T_DES) requires a **24-byte (192-bit) key**.
- **Padding** is automatically added for messages that aren't multiples of 8 bytes.
- **Modes:**
  - `ECB` (Electronic Codebook) – Basic mode without an IV.
  - `CBC` (Cipher Block Chaining) – Requires an **IV**.
  - `OFB` (Output Feedback) – Also requires an **IV**.

## License
This project is licensed under the MIT License.
