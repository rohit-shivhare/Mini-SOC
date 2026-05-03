from cryptography.fernet import Fernet
import os

# Generate and save a key if it doesn't exist
KEY_FILE = 'secret.key'

def load_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, 'wb') as key_file:
            key_file.write(key)
    else:
        with open(KEY_FILE, 'rb') as key_file:
            key = key_file.read()
    return key

def encrypt_file(file_path):
    key = load_key()
    f = Fernet(key)
    
    with open(file_path, 'rb') as file:
        file_data = file.read()
        
    encrypted_data = f.encrypt(file_data)
    
    encrypted_file_path = file_path + ".enc"
    with open(encrypted_file_path, 'wb') as file:
        file.write(encrypted_data)
        
    return encrypted_file_path

def decrypt_file(encrypted_file_path):
    key = load_key()
    f = Fernet(key)
    
    with open(encrypted_file_path, 'rb') as file:
        encrypted_data = file.read()
        
    decrypted_data = f.decrypt(encrypted_data)
    
    # Remove .enc extension
    decrypted_file_path = encrypted_file_path[:-4]
    with open(decrypted_file_path, 'wb') as file:
        file.write(decrypted_data)
        
    return decrypted_file_path
