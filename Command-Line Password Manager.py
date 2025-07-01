import json
import os
import base64
import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from hashlib import sha256

DATA_FILE = "vault.json"

def derive_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=sha256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))

def load_data():
    if not os.path.exists(DATA_FILE):
        return {"salt": base64.b64encode(os.urandom(16)).decode(), "passwords": {}}
    with open(DATA_FILE, "r") as f:
        return json.load(f)

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)

def encrypt_password(fernet, password):
    return fernet.encrypt(password.encode()).decode()

def decrypt_password(fernet, encrypted_password):
    return fernet.decrypt(encrypted_password.encode()).decode()

def add_password(fernet, data):
    site = input("Enter website or app name: ").strip()
    username = input("Enter username: ").strip()
    password = getpass.getpass("Enter password: ").strip()

    encrypted_password = encrypt_password(fernet, password)

    data['passwords'][site] = {
        "username": username,
        "password": encrypted_password
    }
    save_data(data)
    print(f"🔐 Password saved for '{site}'.")

def view_passwords(fernet, data):
    if not data["passwords"]:
        print("⚠️ No passwords saved.")
        return
    for site, creds in data["passwords"].items():
        try:
            decrypted_password = decrypt_password(fernet, creds["password"])
            print(f"\n🔹 Site/App: {site}")
            print(f"   👤 Username: {creds['username']}")
            print(f"   🔑 Password: {decrypted_password}")
        except:
            print(f"❌ Failed to decrypt password for {site}.")

def main():
    print("🔒 Welcome to CLI Password Manager 🔒")
    master_password = getpass.getpass("Enter master password: ")

    data = load_data()
    salt = base64.b64decode(data["salt"])
    key = derive_key(master_password, salt)
    fernet = Fernet(key)

    while True:
        print("\n--- Menu ---")
        print("1. Add new password")
        print("2. View saved passwords")
        print("3. Exit")

        choice = input("Enter choice: ").strip()
        if choice == '1':
            add_password(fernet, data)
        elif choice == '2':
            view_passwords(fernet, data)
        elif choice == '3':
            print("👋 Exiting...")
            break
        else:
            print("❌ Invalid choice. Try again.")

if __name__ == "__main__":
    main()

