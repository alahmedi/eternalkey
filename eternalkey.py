#!/usr/bin/env python3
import time
import os
import argparse
import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

print("EternalKey V3")
print()

def derive_key(password: bytes, salt: bytes, iterations: int = 200000) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password)

def aes_encrypt(data: bytes, password: bytes) -> bytes:
    """
    File format:
      b'EK3AES' (6) | salt (16) | nonce (12) | ciphertext+tag (len)
    """
    salt = os.urandom(16)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, data, None)
    return b'EK3AES' + salt + nonce + ct

def aes_decrypt(blob: bytes, password: bytes) -> bytes:
    if not blob.startswith(b'EK3AES'):
        raise ValueError("invalid file format")
    offset = 6
    salt = blob[offset:offset+16]; offset += 16
    nonce = blob[offset:offset+12]; offset += 12
    ct = blob[offset:]
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)

def wipe_file(file_path):
    try:
        megabyte = 1024 * 1024
        random_data = os.urandom(megabyte)
        with open(file_path, 'wb') as f:
            f.write(random_data)
        os.remove(file_path)
        print(f"successfully wiped {file_path}")
    except IOError as e:
        print(f"an error occurred: {e}")

def main():
    parser = argparse.ArgumentParser(description='perform file operations')
    subparsers = parser.add_subparsers(dest='operation')

    encrypt_parser = subparsers.add_parser('encrypt', help='encrypt a file')
    encrypt_parser.add_argument('file', help='the file to encrypt')

    decrypt_parser = subparsers.add_parser('decrypt', help='decrypt a file')
    decrypt_parser.add_argument('file', help='the file to decrypt')
    decrypt_parser.add_argument('--grab-on', action='store_true', help='prevent auto-wiping of the decrypted file')

    wipe_parser = subparsers.add_parser('wipe', help='wipe a file')
    wipe_parser.add_argument('file', help='the file to wipe')

    help_parser = subparsers.add_parser('help', help='show this help message')

    args = parser.parse_args()

    if args.operation == 'encrypt':
        key = getpass.getpass("secret key: ").encode()
        with open(args.file, 'rb') as f:
            data = f.read()
        encrypted_data = aes_encrypt(data, key)
        with open(args.file, 'wb') as f:
            f.write(encrypted_data)
        print(f"encrypted '{args.file}'")

    elif args.operation == 'decrypt':
        key = getpass.getpass("secret key: ").encode()

        filename = os.path.basename(args.file)
        if filename.startswith('.') and filename.endswith('.enc'):
            decrypted_file_path = os.path.join(os.path.dirname(args.file), filename[1:-4])
        else:
            decrypted_file_path = '/tmp/' + filename

        with open(args.file, 'rb') as f:
            encrypted_data = f.read()
        try:
            decrypted_data = aes_decrypt(encrypted_data, key)
        except (InvalidTag, ValueError):
            print("decryption failed: wrong key or corrupt file")
            return

        # Get the file extension
        _, extension = os.path.splitext(decrypted_file_path)
        whitelist = ['.txt', '.dat', '.decrypted']

        if extension in whitelist:
            # Text file logic
            try:
                decoded_content = decrypted_data.decode('utf-8')
                with open(decrypted_file_path, 'w') as f:
                    f.write(decoded_content)
                print(f"decrypted '{args.file}'. opening with 'more'.")
                time.sleep(1)
                os.system("tput smcup")
                os.system(f"more {decrypted_file_path}")
                if not args.grab_on:
                    wipe_file(decrypted_file_path)
                    os.system("tput rmcup")
                    print("<3")
            except UnicodeDecodeError:
                # It was whitelisted but couldn't be decoded. Treat as binary to be safe.
                with open(decrypted_file_path, 'wb') as f:
                    f.write(decrypted_data)
                print(f"decrypted '{args.file}' to '{decrypted_file_path}'.")
                print("file has a text extension but seems to be binary. using 'open' and wiping after 30 seconds.")
                os.system(f"open {decrypted_file_path}")
                time.sleep(30)
                wipe_file(decrypted_file_path)
        else:
            # Binary file logic
            with open(decrypted_file_path, 'wb') as f:
                f.write(decrypted_data)
            print(f"decrypted '{args.file}' to '{decrypted_file_path}'.")
            print("file type is not whitelisted for 'more'. using 'open' and wiping after 5 seconds. do NOT attempt to edit!")
            os.system(f"open {decrypted_file_path}")
            time.sleep(5)
            wipe_file(decrypted_file_path)

    elif args.operation == 'wipe':
        wipe_file(args.file)

    elif args.operation == 'help':
        parser.print_help()

if __name__ == '__main__':
    main()
