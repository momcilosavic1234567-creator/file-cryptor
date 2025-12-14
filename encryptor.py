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

def process_file(file_path, key, mode='encrypt'):
    """Helper function to perform encryption or decryption on a single file."""
    f = Fernet(key)
    action = f.encrypt if mode == 'encrypt' else f.decrypt
    action_verb = "encrypted" if mode == 'encrypt' else "decrypted"

    try:
        with open(file_path, "rb") as original_file:
            original_data = original_file.read()
        
        processed_data = action(original_data)

        with open(file_path, "wb") as processed_file:
            processed_file.write(processed_data)
        
        print(f"[{action_verb.upper()}] {file_path}")
        return True
    
    except FileNotFoundError:
        print(f"[ERROR] File not found: {file_path}")
    except Exception as e:
        # Catch InvalidToken error on decryption attempt with wrong key/corrupted data
        if mode == 'decrypt' and 'InvalidToken' in str(e):
            print(f"[FAILED] {file_path} (Decryption failed: wrong key or corrupted data)")
        else:
            print(f"[FAILED] {file_path} ({e})")
    return False

# Recursive Directory Processing Function

def process_directory(path, key, mode):
    ignore_files = ['secret.key', 'encryptor.py', 'requirements.txt', '.gitignore']

    print("-" * 50)
    print(f"Starting {mode}ion of directory: {path}")
    print("-" * 50)

    if not os.path.exists(path):
        print(f"[ERROR] Path is not a valid directory: {path}")
        return
    
    processed_count = 0

    # os.walk generates the file names in a directory tree
    for root, dirs, files in os.walk(path):
        for file_name in files:
            if file_name not in ignore_files:
                file_path = os.path.join(root, file_name)
                if process_file(file_path, key, mode):
                    processed_count += 1

    print("-" * 50)
    print(f"Finished {mode}ing {processed_count} files.")

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
    
    subparsers = parser.add_subparsers(dest='command', required=True)
    
    # Sub-parser for KEY generation (No change)
    key_parser = subparsers.add_parser('key', help='Generate a new secret encryption key.')
    key_parser.add_argument(
        '-k', '--keyfile', 
        default='secret.key', 
        help='Name of the key file to create (default: secret.key)'
    )
    
    # Sub-parser for ENCRYPT (Updated to use 'path' and process directory/file)
    enc_parser = subparsers.add_parser('enc', help='Encrypt a file or an entire directory.')
    enc_parser.add_argument(
        'path', 
        help='Path to the file or directory to encrypt.'
    )
    enc_parser.add_argument(
        '-k', '--keyfile', 
        default='secret.key', 
        help='Path to the key file (default: secret.key)'
    )
    
    # Sub-parser for DECRYPT (Updated to use 'path' and process directory/file)
    dec_parser = subparsers.add_parser('dec', help='Decrypt a file or an entire directory.')
    dec_parser.add_argument(
        'path', 
        help='Path to the file or directory to decrypt.'
    )
    dec_parser.add_argument(
        '-k', '--keyfile', 
        default='secret.key', 
        help='Path to the key file (default: secret.key)'
    )
    
    args = parser.parse_args()
    
    if args.command == 'key':
        generate_key(args.keyfile)
    elif args.command == 'enc' or args.command == 'dec':
        mode = 'encrypt' if args.command == 'enc' else 'decrypt'
        key = load_key(args.keyfile)
        
        if os.path.isdir(args.path):
            process_directory(args.path, key, mode)
        else:
            # If it's a file, just process the single file
            process_file(args.path, key, mode)


if __name__ == '__main__':
    main()