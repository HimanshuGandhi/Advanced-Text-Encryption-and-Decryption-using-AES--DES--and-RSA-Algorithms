import os
import tkinter as tk
from tkinter import messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives.hashes import SHA256
from Crypto.Cipher import DES


# AES Enc/Dec
def aes_encrypt_decrypt(text, key, iv=None, operation="encrypt"):
    if operation == "encrypt":
        iv = os.urandom(16)  # Generate IV for encryption
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        text_padded = padder.update(text.encode()) + padder.finalize()
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(text_padded) + encryptor.finalize()
        return ciphertext, iv
    elif operation == "decrypt":
        if iv is None:
            raise ValueError("IV must be provided for decryption.")
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decryptor = cipher.decryptor()
        plaintext_padded = decryptor.update(text) + decryptor.finalize()
        plaintext = unpadder.update(plaintext_padded) + unpadder.finalize()
        return plaintext.decode()


# DES Enc/Dec
def des_encrypt_decrypt(text, key, operation="encrypt"):
    cipher = DES.new(key, DES.MODE_ECB)
    if operation == "encrypt":
        while len(text) % 8 != 0:  # Padding
            text += ' '
        ciphertext = cipher.encrypt(text.encode())
        return ciphertext
    elif operation == "decrypt":
        plaintext = cipher.decrypt(text).decode()
        return plaintext.strip()


# RSA Enc/Dec
def rsa_generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key


def rsa_encrypt_decrypt(text, key, operation="encrypt"):
    if operation == "encrypt":
        ciphertext = key.encrypt(
            text.encode(),
            rsa_padding.OAEP(
                mgf=rsa_padding.MGF1(algorithm=SHA256()),
                algorithm=SHA256(),
                label=None,
            )
        )
        return ciphertext
    elif operation == "decrypt":
        plaintext = key.decrypt(
            text,
            rsa_padding.OAEP(
                mgf=rsa_padding.MGF1(algorithm=SHA256()),
                algorithm=SHA256(),
                label=None,
            )
        )
        return plaintext.decode()


# GUI
def encrypt_decrypt_text():
    text = input_text.get("1.0", "end-1c")
    if not text:
        messagebox.showerror("Input Error", "Please enter some text to encrypt/decrypt.")
        return

    selected_algorithm = algorithm_var.get()
    if selected_algorithm == "AES":
        key = os.urandom(32)  # AES 32-byte key
        try:
            ciphertext, iv = aes_encrypt_decrypt(text, key, "encrypt")
            encrypted_text.set(ciphertext.hex())
            decrypted_text.set(aes_encrypt_decrypt(bytes.fromhex(encrypted_text.get()), key, iv, "decrypt"))
        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))
    elif selected_algorithm == "DES":
        key = os.urandom(8)  # DES 8-byte key
        ciphertext = des_encrypt_decrypt(text, key, "encrypt")
        encrypted_text.set(ciphertext.hex())
        decrypted_text.set(des_encrypt_decrypt(bytes.fromhex(encrypted_text.get()), key, "decrypt"))
    elif selected_algorithm == "RSA":
        private_key, public_key = rsa_generate_keys()
        ciphertext = rsa_encrypt_decrypt(text, public_key, "encrypt")
        encrypted_text.set(ciphertext.hex())
        decrypted_text.set(rsa_encrypt_decrypt(bytes.fromhex(encrypted_text.get()), private_key, "decrypt"))
    else:
        messagebox.showerror("Selection Error", "Please select an encryption algorithm.")

# GUI Setup
root = tk.Tk()
root.title("Text Encryption/Decryption")

# Algo selection
algorithm_var = tk.StringVar(value="AES")
algorithm_label = tk.Label(root, text="Select Algorithm:")
algorithm_label.pack(padx=10, pady=5)

aes_radio = tk.Radiobutton(root, text="AES", variable=algorithm_var, value="AES")
aes_radio.pack(padx=10, pady=2)

des_radio = tk.Radiobutton(root, text="DES", variable=algorithm_var, value="DES")
des_radio.pack(padx=10, pady=2)

rsa_radio = tk.Radiobutton(root, text="RSA", variable=algorithm_var, value="RSA")
rsa_radio.pack(padx=10, pady=2)

# Input 
input_label = tk.Label(root, text="Enter text to encrypt/decrypt:")
input_label.pack(padx=10, pady=5)

input_text = tk.Text(root, height=5, width=40)
input_text.pack(padx=10, pady=5)

# Buttons
encrypt_button = tk.Button(root, text="Encrypt & Decrypt", command=encrypt_decrypt_text)
encrypt_button.pack(padx=10, pady=10)

# Display 
encrypted_text = tk.StringVar()
decrypted_text = tk.StringVar()

encrypted_label = tk.Label(root, text="Encrypted Text:")
encrypted_label.pack(padx=10, pady=5)

encrypted_output = tk.Entry(root, textvariable=encrypted_text, width=50)
encrypted_output.pack(padx=10, pady=5)

decrypted_label = tk.Label(root, text="Decrypted Text:")
decrypted_label.pack(padx=10, pady=5)

decrypted_output = tk.Entry(root, textvariable=decrypted_text, width=50)
decrypted_output.pack(padx=10, pady=5)

root.mainloop()
