from Crypto.Cipher import AES
from stegano import lsb
import base64
from struct import pack
from Crypto.Cipher import Blowfish

def vigenere_encrypt(text, key):
    return ''.join(chr((ord(char) + ord(key[i % len(key)])) % 256) for i, char in enumerate(text))

def vigenere_decrypt(text, key):
    return ''.join(chr((ord(char) - ord(key[i % len(key)])) % 256) for i, char in enumerate(text))

def aes_encrypt(data, key):
    key = key if isinstance(key, bytes) else key.ljust(16)[:16].encode('utf-8')
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
    return cipher.nonce + ciphertext

def aes_decrypt(data, key):
    key = key if isinstance(key, bytes) else key.ljust(16)[:16].encode('utf-8')
    nonce = data[:16]
    ciphertext = data[16:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt(ciphertext).decode('utf-8')

def super_encrypt(message, vigenere_key, aes_key):
    vigenere_encrypted = vigenere_encrypt(message, vigenere_key)
    aes_encrypted = aes_encrypt(vigenere_encrypted, aes_key)
    return base64.b64encode(aes_encrypted).decode('utf-8')

def super_decrypt(encrypted_message, vigenere_key, aes_key):
    encrypted_message_bytes = base64.b64decode(encrypted_message)
    aes_decrypted = aes_decrypt(encrypted_message_bytes, aes_key)
    return vigenere_decrypt(aes_decrypted, vigenere_key)

#YAAAA


# AES untuk Password
def aes_encrypt_password(password, key):
    # Pastikan panjang kunci valid
    if len(key) not in [16, 24, 32]:
        raise ValueError("Panjang kunci AES harus 16, 24, atau 32 byte.")
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    encrypted_password = cipher.encrypt(password.encode())
    return base64.b64encode(nonce + encrypted_password).decode()


# Steganografi
def hide_message_in_image(image_path, message, output_path):
    secret = lsb.hide(image_path, message)
    secret.save(output_path)

def reveal_message_from_image(image_path):
    return lsb.reveal(image_path)

def vigenere_decrypt(text, key):
    return ''.join(chr((ord(char) - ord(key[i % len(key)])) % 256) for i, char in enumerate(text))

def decrypt_message(encrypted_message, vigenere_key, aes_key):
    # Decode Base64 and decrypt with AES
    aes_decrypted = aes_decrypt(base64.b64decode(encrypted_message.encode()), aes_key)
    # Decrypt with Vigenère
    return vigenere_decrypt(aes_decrypted.decode(), vigenere_key)

def blowfish_encrypt(data, key):
    """
    Mengenkripsi data menggunakan algoritma Blowfish.
    - data: Data dalam bentuk bytes yang akan dienkripsi.
    - key: Kunci enkripsi (harus string dengan minimal 4 karakter).
    """
    if not isinstance(data, bytes):
        raise ValueError("Data untuk enkripsi harus berupa bytes.")
    if len(key) < 4:
        raise ValueError("Kunci Blowfish minimal 4 karakter.")
    
    cipher = Blowfish.new(key.encode('utf-8'), Blowfish.MODE_ECB)
    plen = Blowfish.block_size - len(data) % Blowfish.block_size
    padding = pack('b', plen) * plen
    return cipher.encrypt(data + padding)

def blowfish_decrypt(data, key):
    """
    Mendekripsi data menggunakan algoritma Blowfish.
    - data: Data terenkripsi dalam bentuk bytes.
    - key: Kunci enkripsi yang sama digunakan untuk dekripsi.
    """
    if not isinstance(data, bytes):
        raise ValueError("Data untuk dekripsi harus berupa bytes.")
    if len(key) < 4:
        raise ValueError("Kunci Blowfish minimal 4 karakter.")
    
    cipher = Blowfish.new(key.encode('utf-8'), Blowfish.MODE_ECB)
    decrypted_data = cipher.decrypt(data)
    plen = decrypted_data[-1]
    return decrypted_data[:-plen]