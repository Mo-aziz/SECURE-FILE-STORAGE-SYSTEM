
import os
import json
from typing import Tuple, Dict, Optional

from . import rsa
from . import hybrid


DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'data')
USERS_DIR = os.path.join(DATA_DIR, 'users')


def ensure_directories():
   
    os.makedirs(USERS_DIR, exist_ok=True)


def get_user_dir(username: str) -> str:
   
    return os.path.join(USERS_DIR, username)


def get_user_keys_dir(username: str) -> str:
 
    user_dir = get_user_dir(username)
    keys_dir = os.path.join(user_dir, 'keys')
    os.makedirs(keys_dir, exist_ok=True)
    return keys_dir


def get_user_files_dir(username: str) -> str:
   
    user_dir = get_user_dir(username)
    files_dir = os.path.join(user_dir, 'files')
    os.makedirs(files_dir, exist_ok=True)
    return files_dir


def user_exists(username: str) -> bool:
   
    return os.path.isdir(get_user_dir(username))


def create_user(username: str, key_bits: int = 512) -> Tuple[Tuple[int, int], Tuple[int, int]]:
   
    if user_exists(username):
        raise ValueError(f"User {username} already exists")
    
    # Generate keypair
    public_key, private_key = rsa.generate_keypair(key_bits)
    
    # Create user directory
    user_dir = get_user_dir(username)
    os.makedirs(user_dir, exist_ok=True)
    
    # Save keys
    keys_dir = get_user_keys_dir(username)
    
    e, n = public_key
    d, d_n = private_key
    
    # Save public key
    public_key_data = {
        'username': username,
        'e': e,
        'n': n,
        'bits': key_bits
    }
    with open(os.path.join(keys_dir, 'public_key.json'), 'w') as f:
        json.dump(public_key_data, f, indent=2)
    
    # Save private key (in real system, would be encrypted)
    private_key_data = {
        'username': username,
        'd': d,
        'n': d_n,
        'bits': key_bits
    }
    with open(os.path.join(keys_dir, 'private_key.json'), 'w') as f:
        json.dump(private_key_data, f, indent=2)
    
    return public_key, private_key


def get_public_key(username: str) -> Optional[Tuple[int, int]]:
  
    keys_dir = get_user_keys_dir(username)
    public_key_file = os.path.join(keys_dir, 'public_key.json')
    
    if not os.path.exists(public_key_file):
        return None
    
    with open(public_key_file, 'r') as f:
        data = json.load(f)
    
    return (data['e'], data['n'])


def get_private_key(username: str) -> Optional[Tuple[int, int]]:
  
    keys_dir = get_user_keys_dir(username)
    private_key_file = os.path.join(keys_dir, 'private_key.json')
    
    if not os.path.exists(private_key_file):
        return None
    
    with open(private_key_file, 'r') as f:
        data = json.load(f)
    
    return (data['d'], data['n'])


def save_encrypted_file(
    username: str,
    filename: str,
    manifest: Dict
) -> str:

    files_dir = get_user_files_dir(username)
    filepath = os.path.join(files_dir, f"{filename}.json")
    
    with open(filepath, 'w') as f:
        f.write(hybrid.serialize_encrypted_file(manifest))
    
    return filepath


def load_encrypted_file(username: str, filename: str) -> Optional[Dict]:
 
    files_dir = get_user_files_dir(username)
    filepath = os.path.join(files_dir, f"{filename}.json")
    
    if not os.path.exists(filepath):
        return None
    
    with open(filepath, 'r') as f:
        return hybrid.deserialize_encrypted_file(f.read())


def list_user_files(username: str) -> list:
 
    files_dir = get_user_files_dir(username)
    
    if not os.path.exists(files_dir):
        return []
    
    files = []
    for fname in os.listdir(files_dir):
        if fname.endswith('.json'):
            files.append(fname[:-5])  # Remove .json extension
    
    return sorted(files)


def list_users() -> list:
  
    if not os.path.exists(USERS_DIR):
        return []
    
    users = []
    for name in os.listdir(USERS_DIR):
        if os.path.isdir(os.path.join(USERS_DIR, name)):
            users.append(name)
    
    return sorted(users)


def delete_encrypted_file(username: str, filename: str) -> bool:
 
    files_dir = get_user_files_dir(username)
    filepath = os.path.join(files_dir, f"{filename}.json")
    
    if os.path.exists(filepath):
        os.remove(filepath)
        return True
    
    return False


# Initialize on module import
ensure_directories()
