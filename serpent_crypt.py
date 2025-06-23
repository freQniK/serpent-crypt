import argparse
from pyserpent.serpent import Serpent
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import os

BLOCK_SIZE = 16  # Serpent block size is 128 bits (16 bytes)

def encrypt_cbc(serpent_cipher, data, iv):
    encrypted = b''
    previous_block = iv
    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i:i+BLOCK_SIZE]
        block_xored = bytes([_a ^ _b for _a, _b in zip(block, previous_block)])
        encrypted_block = serpent_cipher.encrypt(block_xored)
        encrypted += encrypted_block
        previous_block = encrypted_block
    return encrypted


def decrypt_cbc(serpent_cipher, data, iv):
    decrypted = b''
    previous_block = iv
    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i:i+BLOCK_SIZE]
        decrypted_block = serpent_cipher.decrypt(block)
        block_xored = bytes([_a ^ _b for _a, _b in zip(decrypted_block, previous_block)])
        decrypted += block_xored
        previous_block = block
    return decrypted


def encrypt_file(input_file, output_file, key_file):

    if os.path.exists(key_file):
        print(f"Key file {key_file} exists. Using the existing key.")

        with open(key_file, 'rb') as f:
            key = f.read()
    else:

        key = get_random_bytes(32)  
        with open(key_file, 'wb') as f:
            f.write(key)
        print(f"Generated new key and saved to {key_file}")

    cipher = Serpent(key)

    iv = get_random_bytes(BLOCK_SIZE)

    with open(input_file, 'rb') as f:
        plaintext = f.read()

    padded_plaintext = pad(plaintext, BLOCK_SIZE)

    ciphertext = encrypt_cbc(cipher, padded_plaintext, iv)

    with open(output_file, 'wb') as f:
        f.write(iv)
        f.write(ciphertext)

    print(f"Encryption successful. Output saved to {output_file}")
    print(f"Encryption key (save this securely!): {key.hex()}")

def decrypt_file(input_file, output_file, key_file):
    if not os.path.exists(key_file):
        print(f"Error: Key file {key_file} does not exist.")
        return

    with open(key_file, 'rb') as f:
        key = f.read()

    cipher = Serpent(key)

    with open(input_file, 'rb') as f:
        iv = f.read(BLOCK_SIZE)  
        ciphertext = f.read()
 
    decrypted_data = decrypt_cbc(cipher, ciphertext, iv)
    
    plaintext = unpad(decrypted_data, BLOCK_SIZE)

    with open(output_file, 'wb') as f:
        f.write(plaintext)

    print(f"Decryption successful. Output saved to: {output_file}")

def main():
    parser = argparse.ArgumentParser(description="Encrypt or decrypt files using Serpent (CBC mode) with pyserpent.")
    parser.add_argument('-e', '--encrypt', action='store_true', help="Encrypt a file")
    parser.add_argument('-d', '--decrypt', action='store_true', help="Decrypt a file")
    parser.add_argument('input_file', type=str, help="Input file")
    parser.add_argument('output_file', type=str, help="Output file")
    args = parser.parse_args()

    if args.encrypt and args.decrypt:
        print("Error: Cannot use both -e and -d at the same time.")
        return
    if not args.encrypt and not args.decrypt:
        print("Error: Must specify either -e or -d.")
        return

    key_filename = input("Enter the key file name (for saving or reading): ")

    if args.encrypt:
        encrypt_file(args.input_file, args.output_file, key_filename)
    elif args.decrypt:
        decrypt_file(args.input_file, args.output_file, key_filename)

if __name__ == "__main__":
    main()
