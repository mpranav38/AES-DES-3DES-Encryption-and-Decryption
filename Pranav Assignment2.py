from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from pyDes import des
import math
# Substitution Cipher
def substitution_cipher_encrypt(plaintext):
    # Implementation of substitution cipher encryption
    mapping = {'a': '!', 'b': '@', 'c': '#', 'd': '$', 'e': '%',
               'f': '^', 'g': '&', 'h': '*', 'i': '(', 'j': ')',
               'k': '-', 'l': '+', 'm': '=', 'n': '{', 'o': '}',
               'p': '[', 'q': ']', 'r': '|', 's': '\\', 't': ';',
               'u': ':', 'v': '\'', 'w': '"', 'x': ',', 'y': '.',
               'z': '/'}
    ciphertext = ''.join(mapping.get(char.lower(), char) for char in plaintext)
    return ciphertext

def substitution_cipher_decrypt(ciphertext):
    # Implementation of substitution cipher decryption
    mapping = {'!': 'a', '@': 'b', '#': 'c', '$': 'd', '%': 'e',
               '^': 'f', '&': 'g', '*': 'h', '(': 'i', ')': 'j',
               '-': 'k', '+': 'l', '=': 'm', '{': 'n', '}': 'o',
               '[': 'p', ']': 'q', '|': 'r', '\\': 's', ';': 't',
               ':': 'u', '\'': 'v', '"': 'w', ',': 'x', '.': 'y',
               '/': 'z'}
    plaintext = ''.join(mapping.get(char, char) for char in ciphertext)
    return plaintext

# Shift Cipher
def shift_cipher_encrypt(plaintext, shift):
    # Implementation of shift cipher encryption
    shifted_text = ''
    for char in plaintext:
        if char.isalpha():
            shifted_text += chr((ord(char) - 97 + shift) % 26 + 97) if char.islower() else chr((ord(char) - 65 + shift) % 26 + 65)
        else:
            shifted_text += char
    return shifted_text

def shift_cipher_decrypt(ciphertext, shift):
    # Implementation of shift cipher decryption
    return shift_cipher_encrypt(ciphertext, -shift)

# Permutation Cipher
def permutation_cipher_encrypt(plaintext):
    # Implementation of permutation cipher encryption
    return ''.join(plaintext[i] for i in range(len(plaintext) - 1, -1, -1))

def permutation_cipher_decrypt(ciphertext):
    # Implementation of permutation cipher decryption
    return ''.join(ciphertext[i] for i in range(len(ciphertext) - 1, -1, -1))

# Simple Transposition Cipher
def simple_transposition_encrypt(message, key):
    cipher_text = [''] * key
    for col in range(key):
        pointer = col
        while pointer < len(message):
            cipher_text[col] += message[pointer]
            pointer += key
    return ''.join(cipher_text)

def simple_transposition_decrypt(cipher_text, key):
    num_of_rows = math.ceil(len(cipher_text) / key)
    num_of_shaded_boxes = (num_of_rows * key) - len(cipher_text)
    plaintext = [''] * num_of_rows
    col = 0
    row = 0
    for symbol in cipher_text:
        plaintext[row] += symbol
        row += 1
        if (row == num_of_rows) or (row == num_of_rows - 1 and col >= key - num_of_shaded_boxes):
            row = 0 
            col += 1
    return ''.join(plaintext)

def double_transposition_encrypt(message, key1, key2):
    first_step = simple_transposition_encrypt(message, key1)
    return simple_transposition_encrypt(first_step, key2)

def double_transposition_decrypt(cipher_text, key1, key2):
    first_step = simple_transposition_decrypt(cipher_text, key2)
    return simple_transposition_decrypt(first_step, key1)


# Vigenere Cipher
def vigenere_cipher_encrypt(plaintext, key):
    # Implementation of Vigenere cipher encryption
    encrypted_text = ''
    key_length = len(key)
    for i in range(len(plaintext)):
        key_char = key[i % key_length]
        shift = ord(key_char.lower()) - 97
        if plaintext[i].isalpha():
            encrypted_char = chr((ord(plaintext[i].lower()) - 97 + shift) % 26 + 97) if plaintext[i].islower() else chr((ord(plaintext[i].lower()) - 65 + shift) % 26 + 65)
            encrypted_text += encrypted_char.upper() if plaintext[i].isupper() else encrypted_char
        else:
            encrypted_text += plaintext[i]
    return encrypted_text

def vigenere_cipher_decrypt(ciphertext, key):
    # Implementation of Vigenere cipher decryption
    decrypted_text = ''
    key_length = len(key)
    for i in range(len(ciphertext)):
        key_char = key[i % key_length]
        shift = ord(key_char.lower()) - 97
        if ciphertext[i].isalpha():
            decrypted_char = chr((ord(ciphertext[i].lower()) - 97 - shift) % 26 + 97) if ciphertext[i].islower() else chr((ord(ciphertext[i].lower()) - 65 - shift) % 26 + 65)
            decrypted_text += decrypted_char.upper() if ciphertext[i].isupper() else decrypted_char
        else:
            decrypted_text += ciphertext[i]
    return decrypted_text

# AES Encryption in ECB mode
def aes_ecb_encrypt(plaintext, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext

def aes_ecb_decrypt(ciphertext, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    return plaintext.decode('utf-8')

# AES Encryption in CBC mode
def aes_cbc_encrypt(plaintext, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext

def aes_cbc_decrypt(ciphertext, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    return plaintext.decode('utf-8')

# DES Encryption in ECB mode
def des_ecb_encrypt(plaintext, key):
    cipher = Cipher(algorithms.DES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.DES.block_size).padder()
    padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext

def des_ecb_decrypt(ciphertext, key):
    cipher = Cipher(algorithms.DES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(algorithms.DES.block_size).unpadder()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    return plaintext.decode('utf-8')

# DES Encryption in CBC mode
def des_cbc_encrypt(plaintext, key, iv):
    cipher = Cipher(algorithms.DES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.DES.block_size).padder()
    padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext

def des_cbc_decrypt(ciphertext, key, iv):
    cipher = Cipher(algorithms.DES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(algorithms.DES.block_size).unpadder()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    return plaintext.decode('utf-8')

# 3DES Encryption in ECB mode
def des3_ecb_encrypt(plaintext, key):
    cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.TripleDES.block_size).padder()
    padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext

def des3_ecb_decrypt(ciphertext, key):
    cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(algorithms.TripleDES.block_size).unpadder()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    return plaintext.decode('utf-8')

# 3DES Encryption in CBC mode
def des3_cbc_encrypt(plaintext, key, iv):
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.TripleDES.block_size).padder()
    padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext

def des3_cbc_decrypt(ciphertext, key, iv):
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(algorithms.TripleDES.block_size).unpadder()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    return plaintext.decode('utf-8')

# Main function
def main():
    print("Welcome to Encryption Program")

    while True:
        print("\nChoose an encryption technique:")
        print("1. Substitution Cipher")
        print("2. Shift Cipher")
        print("3. Permutation Cipher")
        print("4. Simple Transposition")
        print("5. Double Transposition")
        print("6. Vigenere Cipher")
        print("7. AES Encryption in ECB mode")
        print("8. AES Encryption in CBC mode")
        print("9. DES Encryption in ECB mode")
        print("10. DES Encryption in CBC mode")
        print("11. 3DES Encryption in ECB mode")
        print("12. 3DES Encryption in CBC mode")
        print("13. Exit")

        choice = int(input("Enter your choice: "))
        if choice in [1, 2, 3, 6]:
            plaintext = input("Enter the message to be encrypted: ")
        elif choice in [7, 8, 9, 10, 11, 12]:
            plaintext = input("Enter the message to be encrypted: ")
            key = input("Enter the encryption key: ")
            if choice in [ 10, 12]:
                iv = input("Enter the initialization vector (IV): ")

        if choice == 1:
            ciphertext = substitution_cipher_encrypt(plaintext)
            print("Encrypted Message:", ciphertext)
            if input("Do you want to decrypt the message? (yes/no): ").lower() == 'yes':
                decrypted_text = substitution_cipher_decrypt(ciphertext)
                print("Decrypted Message:", decrypted_text)
        elif choice == 2:
            shift = int(input("Enter the shift value: "))
            ciphertext = shift_cipher_encrypt(plaintext, shift)
            print("Encrypted Message:", ciphertext)
            if input("Do you want to decrypt the message? (yes/no): ").lower() == 'yes':
                decrypted_text = shift_cipher_decrypt(ciphertext, shift)
                print("Decrypted Message:", decrypted_text)
        elif choice == 3:
            ciphertext = permutation_cipher_encrypt(plaintext)
            print("Encrypted Message:", ciphertext)
            if input("Do you want to decrypt the message? (yes/no): ").lower() == 'yes':
                decrypted_text = permutation_cipher_decrypt(ciphertext)
                print("Decrypted Message:", decrypted_text)
        elif choice == 4:
            message = input("Enter the message to be encrypted: ")
            while len(message) < max(int(choice), 2):
                message = input(f"Enter a message longer than {max(int(choice), 2)} characters: ")
            if input("Do you want to enter an encryption key? (yes/no): ").lower() == 'yes':
                key = int(input("Enter the key (number): "))
            else:
                key = 5  # Default key
            encrypted_message = simple_transposition_encrypt(message, key)
            print(f"Encrypted message: {encrypted_message}")
            if input("Do you want to decrypt the message? (yes/no): ").lower() == 'yes':
                decrypted_message = simple_transposition_decrypt(encrypted_message, key)
                print(f"Decrypted message: {decrypted_message}")
        elif choice == 5:
            message = input("Enter the message to be encrypted: ")
            while len(message) < max(int(choice), 2):
                message = input(f"Enter a message longer than {max(int(choice), 2)} characters: ")
            if input("Do you want to enter the first encryption key? (yes/no): ").lower() == 'yes':
                key1 = int(input("Enter the first key (number): "))
            else:
                key1 = 5  # Default first key
            if input("Do you want to enter the second encryption key? (yes/no): ").lower() == 'yes':
                key2 = int(input("Enter the second key (number): "))
            else:
                key2 = 7  # Default second key
            encrypted_message = double_transposition_encrypt(message, key1, key2)
            print(f"Encrypted message: {encrypted_message}")
            if input("Do you want to decrypt the message? (yes/no): ").lower() == 'yes':
                decrypted_message = double_transposition_decrypt(encrypted_message, key1, key2)
                print(f"Decrypted message: {decrypted_message}")
        elif choice == 6:
            key = input("Enter the Vigenere key: ")
            ciphertext = vigenere_cipher_encrypt(plaintext, key)
            print("Encrypted Message:", ciphertext)
            if input("Do you want to decrypt the message? (yes/no): ").lower() == 'yes':
                decrypted_text = vigenere_cipher_decrypt(ciphertext, key)
                print("Decrypted Message:", decrypted_text)
        elif choice == 7:
            key = input("Enter the AES encryption key (16 bytes in hexadecimal): ")
            key = bytes.fromhex(key)
            ciphertext = aes_ecb_encrypt(plaintext.encode(), key)
            print("Encrypted Message:", ciphertext.hex())
            if input("Do you want to decrypt the message? (yes/no): ").lower() == 'yes':
                decrypted_text = aes_ecb_decrypt(ciphertext, key)
                print("Decrypted Message:", decrypted_text)
        elif choice == 8:
            key = input("Enter the AES encryption key (16 bytes in hexadecimal): ")
            key = bytes.fromhex(key)
            iv = input("Enter the initialization vector (IV) (16 bytes in hexadecimal): ")
            iv = bytes.fromhex(iv)
            ciphertext = aes_cbc_encrypt(plaintext.encode(), key, iv)
            print("Encrypted Message:", ciphertext.hex())
            if input("Do you want to decrypt the message? (yes/no): ").lower() == 'yes':
                decrypted_text = aes_cbc_decrypt(ciphertext, key, iv)
                print("Decrypted Message:", decrypted_text)
        elif choice == 9:
            key = input("Enter the DES encryption key (8 bytes in hexadecimal): ")
            key = bytes.fromhex(key)
            ciphertext = des_ecb_encrypt(plaintext.encode(), key)
            print("Encrypted Message:", ciphertext.hex())
            if input("Do you want to decrypt the message? (yes/no): ").lower() == 'yes':
                decrypted_text = des_ecb_decrypt(ciphertext, key)
                print("Decrypted Message:", decrypted_text)
        elif choice == 10:
            key = input("Enter the DES encryption key (8 bytes in hexadecimal): ")
            key = bytes.fromhex(key)
            iv = input("Enter the initialization vector (IV) (8 bytes in hexadecimal): ")
            iv = bytes.fromhex(iv)
            ciphertext = des_cbc_encrypt(plaintext.encode(), key, iv)
            print("Encrypted Message:", ciphertext.hex())
            if input("Do you want to decrypt the message? (yes/no): ").lower() == 'yes':
                decrypted_text = des_cbc_decrypt(ciphertext, key, iv)
                print("Decrypted Message:", decrypted_text)
        elif choice == 11:
            key = input("Enter the 3DES encryption key (24 bytes in hexadecimal): ")
            key = bytes.fromhex(key)
            ciphertext = des3_ecb_encrypt(plaintext.encode(), key)
            print("Encrypted Message:", ciphertext.hex())
            if input("Do you want to decrypt the message? (yes/no): ").lower() == 'yes':
                decrypted_text = des3_ecb_decrypt(ciphertext, key)
                print("Decrypted Message:", decrypted_text)
        elif choice == 12:
            key = input("Enter the 3DES encryption key (24 bytes in hexadecimal): ")
            key = bytes.fromhex(key)
            iv = input("Enter the initialization vector (IV) (8 bytes in hexadecimal): ")
            iv = bytes.fromhex(iv)
            ciphertext = des3_cbc_encrypt(plaintext.encode(), key, iv)
            print("Encrypted Message:", ciphertext.hex())
            if input("Do you want to decrypt the message? (yes/no): ").lower() == 'yes':
                decrypted_text = des3_cbc_decrypt(ciphertext, key, iv)
                print("Decrypted Message:", decrypted_text)
        elif choice == 13:
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please enter a number between 1 and 13.")

if __name__ == "__main__":
    main()