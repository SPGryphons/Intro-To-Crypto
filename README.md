# Introduction to Cryptography (Python)

## Table of Contents
- [Introduction to Cryptography (Python)](#introduction-to-cryptography-python)
  - [Table of Contents](#table-of-contents)
  - [Cryptography in Python](#cryptography-in-python)
    - [Version](#version)
    - [Packages Required](#packages-required)
  - [Advanced Encryption Standard (AES)](#advanced-encryption-standard-aes)
    - [Process](#process)
    - [Encrypting with AES!](#encrypting-with-aes)
    - [Decrypting with AES](#decrypting-with-aes)
  - [RSA](#rsa)
    - [Generating The Keys](#generating-the-keys)
    - [Storing the Keys](#storing-the-keys)
    - [Encrypting a message sent from Alice to Bob](#encrypting-a-message-sent-from-alice-to-bob)
    - [Implementing Digital Sigantures with SHA](#implementing-digital-sigantures-with-sha)

## Cryptography in Python
### Version
- Before coding your encrpytion algorithms in Python, ensure that you have Python 3.10.0 or newer is installed (You can download the new version of Python from the official Python website [here](https://www.python.org/downloads/release/python-3100/))

### Packages Required
- To import several required libraries to implement encryption algorithms, use the `pip` command to install the following package:

```dotnetcli
pip install pycryptodome
```

## Advanced Encryption Standard (AES)
- AES is an symmetric block cipher popularly chosen by the US government to protect classified information
  - A symmetric cipher is one that uses the same key for encryption and decryption
- It is one of the most secure encryptions due to its key size (128-bit, 256-bit)
- The longer the key used to encrypt the message, the harder it is for the hacker to brute-force the ciphertext!

### Process
- Encrypting with AES involves the following stages:
  - SubBytes
  - ShiftRows
  - MixColumns
  - XOR nth round key
- If you are interested in knowing how AES really works in-depth, you can watch this video [here](https://www.youtube.com/watch?v=O4xNJsjtN6E)!

### Encrypting with AES!
1. Firstly let's import the following modules:

```python
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
```

2. Next we will create a function to take in a message as an argument and code a process to encrypt the message and return the final ciphertext.

```python
# Function to encrypt plaintext using an AES Key 
def aes_encrypt(plaintext, aes_key, iv):
  block_size = 16     # in bytes (1 byte = 8 bits)
  aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
  pad_plaintext = pad(plaintext.encode(), block_size)
  ciphertext = aes_cipher.encrypt(pad_plaintext)
  return ciphertext
```

> NOTE: Don't forget to return your function result!

- There are many "modes" in which AES can encrypt plaintext, one of which shown above is CBC (which stands for Cipher Block Chaining)
- We won't go in-depth into what are the differences between these modes of AES encryptions as the concepts covered are very abstract.
- However, if you must know, here are the different types of modes of AES encryption
  - `AES.MODE_ECB` -> Electronic Code Book
  - `AES.MODE_CFB` -> Cipher Feedback
  - `AES.MODE_OFB` -> Output Feedback
  - `AES.MODE_CTR` -> Counter
- Of course, you are free to experiement with all these different modes, but if you're lost, just stick with CBC!

> You might be wondering what does an IV mean. 
> - IV stands for Initialization Vector is just completely random string that gets encrypted together with the plaintext to ensure that even when encrypted with the same key, it will not produce the exact same result, hence adding an extra layer of difficulty!
> - The IV does not need to be secret, it just needs to be random and unique

3. Now, we will generate the AES keys and IV which will go into the function we just created to get our ciphertext!

```python
# You can generate an AES like the code below, or generate one online!

# This line of code generate a random key string of a default block size of 16 bytes or 128 bytes. You can modify the argument to change the block size of the key you want to generate
aes_key = get_random_bytes(AES.block_size)

# Initialization vectors must always be 16 bytes (128 bits) in length regardless of key size
iv = get_random_bytes(AES.block_size)

# Of course, don't forget your secret message you want to encrypt!
secret_message = "Hello World!"
```

4. Now that you have your AES key and IV in your hands now, let's put them through into the function we just coded and see the results!

```python
# Store the function result in a variable
ciphertext = aes_encrypt(secret_message, aes_key, iv)

# Let's print the result and see it!
print(ciphertext.hex())
```

### Decrypting with AES
- Wait! Don't delete anything just yet! Now that you know how to encrypt your plaintext, how do we decrypt our ciphertext?
- Simple, just reverse everything we did when we coded an encryption function!
- Use the same key and reuse the IV to decrypt the ciphertext you just got from your encrypting code and you should get back the same message.

```python
# Function to decrypt ciphertext using an AES Key 
def decrypt(ciphertext, aes_key, iv):
  block_size = 16     # in bytes (1 byte = 8 bits)
  aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
  decrypted_plaintext = aes_cipher.decrypt(ciphertext)
  plaintext = unpad(decrypted_plaintext, 16).decode()
  return plaintext
```

## RSA
- RSA stands for Rivest-Shamir-Adleman, the three geniuses that created this encryption algorithm that is more secure than AES.
- Why is it more secure? The answer is that it is an asymmetric cipher.
- What's the difference between an asymmetric and a symmetric cipher?
  - Asymmetric ciphers use public and private keys
  - Public keys to encrypt messages and private keys to decrypt messages
- In our following example, we will be using Python to implement RSA in order to encrypt a message and decrypt it between a two parties (Alice and Bob)

### Generating The Keys
- Before we experiment on the RSA algorithm, we will need to generate two pairs of public and private keys for Alice and Bob respectively
- You can search for online RSA Key generators online or you can click on this [link](https://www.devglan.com/online-tools/rsa-encryption-decryption) to visit one!

### Storing the Keys
On your Visual Studio Code workstation, store the two pairs of RSA keys into respective folders for Alice and Bob as shown in the tree directory below:

```dotnetcli
.
├── ./alice/
│   ├── ./alice/alice_public_key.pem
│   └── ./alice/alice_private_key.pem
└── ./bob/
    ├── ./bob/bob_public_key.pem
    └── ./bob/bob_private_key.pem 
```

Copy and paste the keys into these files

### Encrypting a message sent from Alice to Bob
- To send a message from Alice to Bob securely, you will need to encrypt the message using Bob's public key and decrypt it using Bob's private key.
- Vice versa, to send a message securely from Bob to Aliice, you will need Alice's public key to encrypt the message and her private key to decrypt it

1. Firstly, import the following modules:


```python
from Cryptodome.PublicKey import RSA, PKCS1_OAEP
from Cryptodome.Cipher import PKCS1_OAEP
```

2. Next, we will need to load Bob's public and private key into our Python script. This can be done by opening and reading the contents of the PEM files under the Bob folder

```python
# Reading the bytes of the PEM file of Bob's public key
bob_public_key_bytes = open("./bob/bob_public_key.pem", "rb").read()

# Importing Bob's public key to be used to encrypt the message
bob_public_key = RSA.import_key(bob_public_key_bytes)

# Reading the bytes of the PEM file of Bob's private key
bob_private_key_bytes = open("./bob/bob_private_key.pem", "rb").read()

# Importing Bob's private key to be used to decrypt the message
bob_private_key = RSA.import_key(bob_private_key_bytes)
```

3. Now that we have loaded Bob's public and private key into our Python script, we can now encrypt a message from Alice to Bob using Bob's public key

```python
def encrypt(plaintext, public_key):
  cipher = PKCS1_OAEP.new(public_key)
  ciphertext = cipher.encrypt(plaintext)
  return ciphertext
```

> PKCS1 stands for the Public Key Cryptography Standards which provides recommendations for implementing RSA for public key infratstructure

4. Now, let's apply the function to encrypt our message that we want to send from Alice to Bob!
```python
secret_message = "Meet me at 8pm at the bar"
ciphertext = encrypt(secret_message, bob_public_key)
print(ciphertext.hex())
```

5. To test if our RSA public and private keys are indeed linked to one another, if Bob's public key is used to encrypt the message, his private key should be able to decrypt the message to get your original message.

```python
def decrypt(ciphertext, private_key):
  cipher = PKCS1_OAEP.new(private_key)
  plaintext = cipher.decrypt(ciphertext)
  return plaintext

# Run the function!
original_message = decrypt(ciphertext, bob_private_key)

# Test the output!
print(original_message)
```

### Implementing Digital Sigantures with SHA
- Digital signatures are made by signing a hash using the sender's private key. The signature is then verified using the sender's public key. If the signature is indeed verified, it proves that the message has not been tampered with.

1. To start, import the following modules into your Python code:

```python
from Cryptodome.Hash import SHA256
from Cryptodome.Signature import PKCS1_v1_5
```

2. Next, we will code a function that will generate a hash/message digest that will be linked to the message

```python
# Function to generate a new SHA-256 hash
def generate_hash(message):
  digest = SHA256.new()
  digest.update(message.encode())
  return digest
```

3. Now, we will generate a digital signature by using Alice's private key (In this scenario, Alice is still sending a message to Bob). Let's create a function to sign the hash in order to generate the signature. Remember to import Alice's keys!

```python
# Import Alice's public key
alice_public_key_bytes = open("./alice/alice_public_key.pem", "rb").read()
alice_public_key = RSA.import_key(alice_public_key_bytes)

# Import Alice's private key
alice_private_key_bytes = open("./alice/alice_private_key.pem", "rb").read()
alice_private_key = RSA.import_key(alice_private_key_bytes)
```

```python
# Function to generate a siganture by signing the hash using Alice's private key
def generate_signature(hash, private_key):
  signer = PKCS1_v1_5.new(private_key)
  signature = signer.sign(hash)
  return signature
```
> Remember, to sign a message, use the sender's public key

4. Store the result of the hash and signature functions into the variables

```python
generated_hash = generate_hash(secret_message)
signature = generate_signature(generated_hash, alice_private_key)

# Check out the output!
print(generated_hash)
print(signature)
```

5. Now, let's code a function to verify the signature using Alice's public key. If the signature is verified, it proves that the message has not been tampered with.

```python
# Function to verify the signature using Alice's public key
def verify_signature(hash, signature, public_key):
  verifier = PKCS1_v1_5.new(public_key)
  try:
    verifier.verify(hash, signature)
    return True   # return true if signature is verified
  except:
    return False  # return false if signature is not verified
```

6. Let's test the function by passing in the hash, signature and Alice's public key

```python
verified = verify_signature(generated_hash, signature, alice_public_key)
if verified:
  print("Signature is verified!")
else:
  print("Signature is not verified!")
```
