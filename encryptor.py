import os
import sys
import argparse
import random # New Import for generating random data
from cryptography.fernet import Fernet

# --- 1. Core Security Functions ---

def generate_key(key_file="secret.key"):
    """Generates a Fernet key and saves it to a file."""
    key = Fernet.generate_key()
    with open(key_file, "wb") as f:
        f.write(key)
    print(f"[SUCCESS] New key generated and saved to: {key_file}")
    
def load_key(key_file="secret.key"):
    """Loads the key from the specified file."""
    try:
        with open(key_file, "rb") as f:
            return f.read()
        # 
    except FileNotFoundError:
        print(f"[ERROR] Key file '{key_file}' not found. Generate a key first.")
        sys.exit(1)

def secure_delete(file_path, passes=3):
    """
    Overwrites a file with random data multiple times before deleting it.
    This prevents easy recovery of the original data.
    """
    if not os.path.exists(file_path):
        return

    try:
        file_size = os.path.getsize(file_path)
        
        with open(file_path, "wb") as f:
            for _ in range(passes):
                # Seek to the beginning and overwrite with random bytes
                f.seek(0)
                random_data = os.urandom(file_size)
                f.write(random_data)
                f.flush() # Force write to disk
                
        os.remove(file_path) # Finally, delete the file's directory entry
        print(f"[SECURE_DELETE] {file_path}")
        return True
    
    except Exception as e:
        print(f"[ERROR] Secure deletion failed for {file_path}: {e}")
        return False

# --- 2. Cryptography and Processing Functions ---

def process_file(file_path, key, mode='encrypt', secure_del=False):
    """Helper function to perform encryption or decryption on a single file."""
    
    # Check if the file should be securely deleted AFTER encryption
    if mode == 'encrypt' and secure_del:
        temp_file_path = file_path + ".temp_original"
        # Rename original file so we can encrypt the newly created file later
        os.rename(file_path, temp_file_path)
    else:
        temp_file_path = file_path # In decryption mode or non-secure encryption, we work on the original file
    
    # Load key and set action
    f = Fernet(key)
    action = f.encrypt if mode == 'encrypt' else f.decrypt
    action_verb = "encrypted" if mode == 'encrypt' else "decrypted"
    
    try:
        with open(temp_file_path, "rb") as original_file:
            original_data = original_file.read()
        
        processed_data = action(original_data)
        
        # Write processed data (encrypted or decrypted)
        if mode == 'encrypt' and secure_del:
             # If securely deleting, write encrypted data to the original file name
             with open(file_path, "wb") as processed_file:
                 processed_file.write(processed_data)
             
             # Securely delete the temporary file containing the original data
             secure_delete(temp_file_path)
        else:
            # If decrypting or not using secure delete, overwrite the temp/original file
            with open(temp_file_path, "wb") as processed_file:
                processed_file.write(processed_data)
            
        print(f"[{action_verb.upper()}] {file_path}")
        return True

    except Exception as e:
        # Simplified error handling for brevity
        print(f"[FAILED] {file_path} (Failed due to: {e})")
        # If secure delete was set, attempt to recover the original name if temp exists
        if mode == 'encrypt' and secure_del and os.path.exists(temp_file_path):
            os.rename(temp_file_path, file_path)
            print(f"[RECOVER] Restored original file name: {file_path}")
    return False


def process_directory(path, key, mode, secure_del=False):
    """Recursively walks a directory and processes all files."""
    
    ignore_files = ['secret.key', 'encryptor.py', 'requirements.txt', '.gitignore']
    
    print("-" * 50)
    print(f"Starting {mode}ion of directory: {path}")
    print(f"Secure Delete: {'Yes' if secure_del and mode == 'encrypt' else 'No'}")
    print("-" * 50)
    
    if not os.path.isdir(path):
        print(f"[ERROR] Path is not a valid directory: {path}")
        return

    processed_count = 0
    
    for root, dirs, files in os.walk(path):
        for file_name in files:
            if file_name not in ignore_files:
                file_path = os.path.join(root, file_name)
                # Pass the secure_del flag to the file processing function
                if process_file(file_path, key, mode, secure_del): 
                    processed_count += 1
                
    print("-" * 50)
    print(f"Finished {mode}ing {processed_count} files.")


# --- 3. Main Execution and Argument Parsing (Updated) ---

def main():
    parser = argparse.ArgumentParser(
        description="Simple CLI tool for Fernet file encryption/decryption."
    )
    
    subparsers = parser.add_subparsers(dest='command', required=True)
    
    # Sub-parser for KEY generation
    key_parser = subparsers.add_parser('key', help='Generate a new secret encryption key.')
    key_parser.add_argument(
        '-k', '--keyfile', 
        default='secret.key', 
        help='Name of the key file to create (default: secret.key)'
    )
    
    # Sub-parser for ENCRYPT (Added --secure-delete flag)
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
    enc_parser.add_argument(
        '--secure-delete', 
        action='store_true', 
        help='Use secure deletion on the original unencrypted file.'
    )
    
    # Sub-parser for DECRYPT (No change, secure deletion not applicable)
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
        
        # Determine secure_delete setting (only applicable for 'enc' command)
        secure_del = args.secure_delete if args.command == 'enc' else False
        
        if os.path.isdir(args.path):
            process_directory(args.path, key, mode, secure_del)
        else:
            process_file(args.path, key, mode, secure_del)


if __name__ == '__main__':
    main()