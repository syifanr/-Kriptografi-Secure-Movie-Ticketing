import json
from cryptography_utils import super_encrypt, super_decrypt

USER_DB_PATH = "users.json"
DEFAULT_AES_KEY = b"1234567890123456"  # Default AES key sepanjang 16 byte
DEFAULT_VIGENERE_KEY = "vigenere_key"  # Default Vigenere key

def ensure_admin_exists(user_db_path, admin_password, aes_key=DEFAULT_AES_KEY, vigenere_key=DEFAULT_VIGENERE_KEY):
    try:
        with open(user_db_path, "r") as f:
            users = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        users = {}

    if "admin" not in users:
        encrypted_password = super_encrypt(admin_password, vigenere_key, aes_key)
        users["admin"] = {"password": encrypted_password, "role": "admin"}
        with open(user_db_path, "w") as f:
            json.dump(users, f, indent=4)

def authenticate_user(username, password, aes_key=DEFAULT_AES_KEY, vigenere_key=DEFAULT_VIGENERE_KEY):
    try:
        # Membaca file users.json
        with open(USER_DB_PATH, "r") as f:
            users = json.load(f)

        # Cek apakah username ada di database
        if username in users:
            # Mendekripsi password terenkripsi
            stored_password = users[username]["password"]
            decrypted_password = super_decrypt(stored_password, vigenere_key, aes_key)

            # Membandingkan password input dengan hasil dekripsi
            if decrypted_password == password:
                return True, users[username]["role"]
    except Exception as e:
        print(f"Authentication error: {e}")

    return False, None

def register_user(username, password, role, aes_key=DEFAULT_AES_KEY, vigenere_key=DEFAULT_VIGENERE_KEY):
    # Validasi input username dan password
    if len(username) < 3:
        return False, "Username harus minimal 3 karakter."
    if len(password) < 6:
        return False, "Password harus minimal 6 karakter."
    
    try:
        # Membaca file users.json (jika ada)
        with open(USER_DB_PATH, "r") as f:
            users = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        users = {}

    # Cek apakah username sudah terdaftar
    if username in users:
        return False, "Username sudah terdaftar."

    # Enkripsi password sebelum disimpan
    encrypted_password = super_encrypt(password, vigenere_key, aes_key)
    users[username] = {"password": encrypted_password, "role": role}

    try:
        # Simpan data pengguna baru ke file users.json
        with open(USER_DB_PATH, "w") as f:
            json.dump(users, f, indent=4)
    except Exception as e:
        return False, f"Gagal menyimpan data pengguna: {e}"

    return True, "Registrasi berhasil!"


