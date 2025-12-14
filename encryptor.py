import os
import sys
import argparse
from cryptography.fernet import Fernet

# Core Cryptography Functions

def generate_key(key_file="secret.key"):
    """Generate a new Fernet key."""
    key = Fernet.generate_key()
    with open(key_file, 'wb') as f:
        f.write(key)
    print(f"[SUCCESS] Key generated and saved to {key_file}")

def load_key(key_file="secret.key"):
    """Loads the key from the specified file."""
    try:
        with open(key_file, "rb") as f:
            # ADDED .strip() to remove potential leading/trailing whitespace/newlines
            return f.read().strip() 
    except FileNotFoundError:
        print(f"[ERROR] Key file '{key_file}' not found. Generate a key first.")
        sys.exit(1)

def encrypt_file(file_path, key):
    """Reads a file and encrypts its contents and overwrites the original file."""
    f = Fernet(key)
    try:
        with open(file_path, "rb") as original_file:
            original_data = original_file.read()

        encrypted_data = f.encrypt(original_data)

        with open(file_path, "wb") as encrypted_file:
            encrypted_file.write(encrypted_data)

        print(f"[SUCCESS] File encrypted: {file_path}")
    
    except FileNotFoundError:
        print(f"[ERROR] File not found: {file_path}")
    except Exception as e:
        print(f"[ERROR] Encryption failed: {e}")

def decrypt_file(file_path, key):
    """Reads an encrypted file and decrypts its contents and overwrites the original file."""
    f = Fernet(key)
    try:
        with open(file_path, "rb") as encrypted_file:
            encrypted_data = encrypted_file.read()

        # The decrypt method handles the authentication check (MAC)
        decrypted_data = f.decrypt(encrypted_data)

        with open(file_path, "wb") as decrypted_file:
            decrypted_file.write(decrypted_data)

        print(f"[SUCCESS] File decrypted: {file_path}")
    
    except FileNotFoundError:
        print(f"[ERROR] File not found: {file_path}")
    except Exception as e:
        print(f"[ERROR] Decryption failed. Check your key file or if the file is corrupted. {e}")

# 2. Main execution and argument parsing

def main():
    parser = argparse.ArgumentParser(
        description="Simple CLI tool for Fernet file encryption/decryption."
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subparser for key generation
    key_parser = subparsers.add_parser('key', help='Generate a new secret encryption key')
    key_parser.add_argument(
        '-k', '--keyfile',
        default='secret.key',
        help='Name of the key file to create (default: secret.key)'
    )

    # Subparser for encryption
    enc_parser = subparsers.add_parser('enc', help='Encrypt a file')
    enc_parser.add_argument(
        'file',
        help='Path to the file to encrypt'
    )
    enc_parser.add_argument(
        '-k', '--keyfile',
        default='secret.key',
        help='Path to the key file (default: secret.key)'
    )

    # Subparser for decryption
    dec_parser = subparsers.add_parser('dec', help='Decrypt a file')
    dec_parser.add_argument(
        'file',
        help='Path to the file to decrypt'
    )
    dec_parser.add_argument(
        '-k', '--keyfile',
        default='secret.key',
        help='Path to the key file (default: secret.key)'
    )

    args = parser.parse_args()

    if args.command == 'key':
        generate_key(args.keyfile)
    elif args.command == 'enc':
        key = load_key(args.keyfile)
        encrypt_file(args.file, key)
    elif args.command == 'dec':
        key = load_key(args.keyfile)
        decrypt_file(args.file, key)
    
if __name__ == "__main__":
    main()