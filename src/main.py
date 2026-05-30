import sys
import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src import storage
from src import hybrid
from src import rsa
from src import aes
from src import encoding


def clean_input_value(value: str) -> str:
    "Trim whitespace and optional wrapping quotes from CLI input."
    return value.strip().strip('"').strip("'")


def clean_path_input(value: str) -> str:
    "Normalize CLI path input to an absolute path."
    return os.path.abspath(os.path.expanduser(clean_input_value(value)))


def print_header(title: str):
    "Print a formatted section header."
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def print_section(title: str):
    "Print a formatted subsection header."
    print(f"\n--- {title} ---")


def menu_main():
    "Main menu."
    while True:
        print_header("SECURE FILE STORAGE SYSTEM")
        print("""
1. User Management
2. File Operations (Encrypt/Decrypt)
3. System Info
4. Exit
        """)
        choice = input("Select option (1-4): ").strip()
        
        if choice == '1':
            menu_users()
        elif choice == '2':
            menu_files()
        elif choice == '3':
            menu_info()
        elif choice == '4':
            print("\nGoodbye!")
            sys.exit(0)
        else:
            print("Invalid option. Please try again.")


def menu_users():
    "User management menu."
    while True:
        print_header("USER MANAGEMENT")
        print("""
1. Register New User
2. List Users
3. View User Public Key
4. Back to Main Menu
        """)
        choice = input("Select option (1-4): ").strip()
        
        if choice == '1':
            register_user()
        elif choice == '2':
            list_users()
        elif choice == '3':
            view_public_key()
        elif choice == '4':
            return
        else:
            print("Invalid option.")


def menu_files():
    "File operations menu."
    while True:
        print_header("FILE OPERATIONS")
        print("""
1. Encrypt a File
2. Decrypt a File
3. List My Files
4. View File Details
5. Back to Main Menu
        """)
        choice = input("Select option (1-5): ").strip()
        
        if choice == '1':
            encrypt_file_ui()
        elif choice == '2':
            decrypt_file_ui()
        elif choice == '3':
            list_files_ui()
        elif choice == '4':
            view_file_details_ui()
        elif choice == '5':
            return
        else:
            print("Invalid option.")


def menu_info():
    "System information menu."
    print_header("SYSTEM INFORMATION")
    print("""
SECURE FILE STORAGE SYSTEM - Hybrid RSA/AES Cryptography

BUSINESS MODEL: Secure File Storage
- Users have RSA keypairs (public/private)
- Each file encrypted with a unique AES-128 session key
- AES session keys encrypted with recipient RSA public key
- Files stored with encrypted bundle (AES ciphertext + RSA-encrypted key)

ENCRYPTION WORKFLOW:
1. User A generates random AES-128 session key
2. User A encrypts file content using AES-CBC
3. User A encrypts AES session key using User B's RSA public key
4. Bundle stored: [RSA-encrypted key, AES IV, AES ciphertext]

DECRYPTION WORKFLOW:
1. User B retrieves stored encrypted bundle
2. User B decrypts AES session key using their RSA private key
3. User B decrypts file content using AES-CBC with recovered key
4. Original plaintext recovered

ENCODING SCHEME:
- Plaintext: UTF-8 (human-readable)
- Binary artifacts (ciphertext, keys): Base64 (safe for storage/transmission)

CRYPTOGRAPHIC PRIMITIVES:
RSA-512:
- Prime generation via Miller-Rabin
- Key generation: e=65537, d via modular inverse
- Manual modular exponentiation (repeated squaring)
- NO built-in pow(a,b,m) - fully from scratch

AES-128:
- 10 rounds, 128-bit key
- Full key expansion (KeySchedule)
- SubBytes (S-box), ShiftRows, MixColumns, AddRoundKey
- CBC mode with PKCS#7 padding
- All tables and operations from scratch

TECHNOLOGY:
- Language: Python 3
- No external crypto libraries
- All algorithms implemented manually
    """)
    input("\nPress Enter to return to main menu...")


def register_user():
    "Register a new user and generate keypair."
    print_section("Register New User")
    
    username = input("Enter username: ").strip()
    if not username:
        print("Username cannot be empty.")
        return
    
    if storage.user_exists(username):
        print(f"User '{username}' already exists.")
        return
    
    print(f"\nGenerating RSA-512 keypair for '{username}'...")
    print("(This may take a moment...)")
    
    try:
        public_key, private_key = storage.create_user(username, key_bits=512)
        e, n = public_key
        
        print(f"\nUser '{username}' created successfully!")
        print(f"  Public exponent (e):  {e}")
        print(f"  Modulus (n) bits:     {n.bit_length()}")
        print(f"  Keys saved in:        {storage.get_user_keys_dir(username)}")
    except Exception as ex:
        print(f"Error registering user: {ex}")


def list_users():
    "List all registered users."
    print_section("Registered Users")
    
    users = storage.list_users()
    if not users:
        print("No users registered yet.")
        return
    
    for i, username in enumerate(users, 1):
        public_key = storage.get_public_key(username)
        if public_key:
            e, n = public_key
            print(f"{i}. {username}")
            print(f"   Modulus bits: {n.bit_length()}")
        else:
            print(f"{i}. {username} (keys not found)")


def view_public_key():
    "Display a user's public key."
    print_section("View Public Key")
    
    username = input("Enter username: ").strip()
    if not username:
        print("Username cannot be empty.")
        return
    
    public_key = storage.get_public_key(username)
    if not public_key:
        print(f"User '{username}' not found or has no public key.")
        return
    
    e, n = public_key
    print(f"\nPublic Key for '{username}':")
    print(f"  e (exponent): {e}")
    print(f"  n (modulus):  {n}")
    print(f"  n bit length: {n.bit_length()}")
    print(f"\n(This key can be shared to encrypt files for this user)")


def encrypt_file_ui():
    "Encrypt a file using hybrid RSA+AES."
    print_section("Encrypt a File")
    
    # Get sender
    sender = input("Your username (who is encrypting): ").strip()
    if not storage.user_exists(sender):
        print(f"User '{sender}' not found.")
        return
    
    # Get recipient
    recipient = input("Recipient username (who can decrypt): ").strip()
    recipient_public_key = storage.get_public_key(recipient)
    if not recipient_public_key:
        print(f"User '{recipient}' not found.")
        return
    
    # Get file to encrypt
   
    file_path = clean_path_input(input("Path to file to encrypt: "))
    if not os.path.isfile(file_path):
        print(f"File '{file_path}' not found.")
        return
    
    # Get output filename
    output_name = input("Name for encrypted file (without extension): ").strip()
    if not output_name:
        output_name = os.path.splitext(os.path.basename(file_path))[0] + "_encrypted"
    
    try:
        # Read plaintext
        with open(file_path, 'rb') as f:
            plaintext = f.read()
        
        original_size = len(plaintext)
        
        print(f"\nEncrypting {original_size} bytes...")
        print("  1. Generating AES-128 session key...")
        print("  2. Encrypting file with AES-CBC...")
        print("  3. Encrypting session key with RSA...")
        
        # Encrypt using hybrid system
        encrypted_bundle = hybrid.encrypt_file(plaintext, recipient_public_key)
        
        # Create manifest
        manifest = hybrid.create_encrypted_file_manifest(
            original_filename=os.path.basename(file_path),
            plaintext_size=original_size,
            encrypted_bundle=encrypted_bundle,
            sender_name=sender,
            recipient_name=recipient
        )
        
        # Save encrypted file
        storage.save_encrypted_file(recipient, output_name, manifest)
        
        encrypted_size = len(encoding.from_base64(encrypted_bundle['aes_ciphertext']))
        
        print(f"\nFile encrypted successfully!")
        print(f"  Original size:    {original_size} bytes")
        print(f"  Encrypted size:   {encrypted_size} bytes")
        print(f"  Saved as:         {output_name}.json")
        print(f"  Stored in:        {storage.get_user_files_dir(recipient)}")
        print(f"\n  Encryption details:")
        print(f"    - AES-128-CBC for file content")
        print(f"    - RSA-512 for AES key protection")
        print(f"    - Base64 encoding for storage")
        
    except Exception as ex:
        print(f"Error encrypting file: {ex}")


def decrypt_file_ui():
    "Decrypt a file using hybrid RSA+AES."
    print_section("Decrypt a File")
    
    # Get recipient (who owns the file and can decrypt)
    recipient = input("Your username (owner of encrypted file): ").strip()
    if not storage.user_exists(recipient):
        print(f"User '{recipient}' not found.")
        return
    
    # Get encrypted file
    files = storage.list_user_files(recipient)
    if not files:
        print(f"User '{recipient}' has no encrypted files.")
        return
    
    print(f"\nAvailable files for {recipient}:")
    for i, fname in enumerate(files, 1):
        print(f"  {i}. {fname}")
    
    file_choice = clean_input_value(input("Enter file name to decrypt: "))
    manifest = storage.load_encrypted_file(recipient, file_choice)
    if not manifest:
        print(f"File '{file_choice}' not found.")
        return
    
    try:
        # Get private key
        private_key = storage.get_private_key(recipient)
        if not private_key:
            print(f"Private key for '{recipient}' not found.")
            return
        
        print(f"\nDecrypting...")
        print("  1. Decrypting AES session key with RSA...")
        print("  2. Decrypting file with AES-CBC...")
        
        # Decrypt using hybrid system
        plaintext = hybrid.decrypt_file(manifest['encrypted_bundle'], private_key)
        
        # Get output filename
        original_name = manifest['original_filename']
        # If it is a .docx save directly into recipient's files folder
        if original_name.lower().endswith('.docx'):
            files_dir = storage.get_user_files_dir(recipient)
            output_path = os.path.join(files_dir, original_name)
        else:
            output_path = clean_input_value(input(f"Save as (default: {original_name}): "))
            if not output_path:
                output_path = original_name
            output_path = clean_path_input(output_path)

        # Write decrypted file
        with open(output_path, 'wb') as f:
            f.write(plaintext)
        
        print(f"\n File decrypted successfully!")
        print(f"  Decrypted size: {len(plaintext)} bytes")
        print(f"  Saved as:       {output_path}")
        print(f"  Original:       {manifest['original_filename']}")
        print(f"  From:           {manifest['sender']}")
        
    except Exception as ex:
        print(f"Error decrypting file: {ex}")


def list_files_ui():
    "List encrypted files for a user."
    print_section("My Files")
    
    username = input("Enter username: ").strip()
    if not storage.user_exists(username):
        print(f"User '{username}' not found.")
        return
    
    files = storage.list_user_files(username)
    if not files:
        print(f"User '{username}' has no encrypted files.")
        return
    
    print(f"\nEncrypted files for {username}:")
    for i, fname in enumerate(files, 1):
        manifest = storage.load_encrypted_file(username, fname)
        if manifest:
            original = manifest.get('original_filename', 'Unknown')
            sender = manifest.get('sender', 'Unknown')
            size = manifest.get('plaintext_size', 0)
            print(f"{i}. {fname}")
            print(f"   From:     {sender}")
            print(f"   Original: {original}")
            print(f"   Size:     {size} bytes")


def view_file_details_ui():
    "Display details about an encrypted file."
    print_section("File Details")
    
    username = clean_input_value(input("Username: "))
    filename = clean_input_value(input("File name: "))
    
    manifest = storage.load_encrypted_file(username, filename)
    if not manifest:
        print("File not found.")
        return
    
    print(f"\nFile Details: {filename}")
    print(f"  Original filename:  {manifest.get('original_filename')}")
    print(f"  Original size:      {manifest.get('plaintext_size')} bytes")
    print(f"  Encrypted size:     {manifest.get('ciphertext_size')} bytes")
    print(f"  Encryption method:  {manifest.get('encryption_method')}")
    print(f"  AES key size:       {manifest.get('aes_key_bits')} bits")
    print(f"  From:               {manifest.get('sender')}")
    print(f"  To:                 {manifest.get('recipient')}")
    
    print(f"\nEncrypted bundle structure:")
    bundle = manifest.get('encrypted_bundle', {})
    for key, value in bundle.items():
        decoded = encoding.from_base64(value)
        print(f"  {key}:")
        print(f"    - Encoded length: {len(value)} chars (Base64)")
        print(f"    - Decoded length: {len(decoded)} bytes")
        print(f"    - First 32 chars: {value[:32]}...")


def main():
    "Main entry point."
    try:
        menu_main()
    except KeyboardInterrupt:
        print("\n\nInterrupted. Goodbye!")
        sys.exit(0)
    except Exception as ex:
        print(f"\nFatal error: {ex}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
