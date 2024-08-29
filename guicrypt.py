import customtkinter as ctk
from tkinter import messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import base64

def encrypt_message(message, password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()
    encrypted_message = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(salt + iv + encrypted_message).decode()

def decrypt_message(encrypted_message, password):
    encrypted_message = base64.b64decode(encrypted_message)
    salt = encrypted_message[:16]
    iv = encrypted_message[16:32]
    encrypted_data = encrypted_message[32:]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data.decode()

def on_encrypt():
    message = message_entry.get("1.0", "end-1c").strip()
    password = password_entry.get()
    
    if not message or not password:
        messagebox.showerror("Input Error", "Message and password fields cannot be empty.")
        return
    
    try:
        encrypted_message = encrypt_message(message, password)
        output_text.delete("1.0", "end")
        output_text.insert("end", encrypted_message)
        password_entry.delete(0, "end")  # Clear the password field
    except Exception as e:
        messagebox.showerror("Encryption Error", str(e))

def on_decrypt():
    encrypted_message = message_entry.get("1.0", "end-1c").strip()
    password = password_entry.get()
    
    if not encrypted_message or not password:
        messagebox.showerror("Input Error", "Encrypted message and password fields cannot be empty.")
        return
    
    try:
        decrypted_message = decrypt_message(encrypted_message, password)
        output_text.delete("1.0", "end")
        output_text.insert("end", decrypted_message)
        password_entry.delete(0, "end")  # Clear the password field
    except Exception as e:
        messagebox.showerror("Decryption Error", str(e))

def clear_entries():
    message_entry.delete("1.0", "end")
    password_entry.delete(0, "end")
    output_text.delete("1.0", "end")

def copy_to_clipboard():
    output_message = output_text.get("1.0", "end-1c").strip()
    if output_message:
        root.clipboard_clear()
        root.clipboard_append(output_message)
        messagebox.showinfo("Copied", "Message copied to clipboard!")
    else:
        messagebox.showwarning("No Output", "There is no message to copy.")

# Initialize the main window
ctk.set_appearance_mode("dark")  # Set dark mode
ctk.set_default_color_theme("blue")  # Set color theme

root = ctk.CTk()
root.title("Interactive Cryptography GUI")
root.geometry("600x600")
root.resizable(False, False)

# Create widgets
ctk.CTkLabel(root, text="Message/Encrypted Message:", font=("Arial", 16)).pack(pady=10)
message_entry = ctk.CTkTextbox(root, wrap="word", height=120, font=("Arial", 14))
message_entry.pack(pady=10, padx=10, fill="both", expand=True)

ctk.CTkLabel(root, text="Password:", font=("Arial", 16)).pack(pady=10)
password_entry = ctk.CTkEntry(root, show="*", font=("Arial", 14), width=400)
password_entry.pack(pady=10)

button_frame = ctk.CTkFrame(root)
button_frame.pack(pady=20)

encrypt_button = ctk.CTkButton(button_frame, text="Encrypt", command=on_encrypt, width=120)
encrypt_button.pack(side="left", padx=10)

decrypt_button = ctk.CTkButton(button_frame, text="Decrypt", command=on_decrypt, width=120)
decrypt_button.pack(side="left", padx=10)

clear_button = ctk.CTkButton(button_frame, text="Clear", command=clear_entries, width=120)
clear_button.pack(side="left", padx=10)

copy_button = ctk.CTkButton(button_frame, text="Copy to Clipboard", command=copy_to_clipboard, width=120)
copy_button.pack(side="left", padx=10)

ctk.CTkLabel(root, text="Output:", font=("Arial", 16)).pack(pady=10)
output_text = ctk.CTkTextbox(root, wrap="word", height=120, font=("Arial", 14))
output_text.pack(pady=10, padx=10, fill="both", expand=True)

# Start the main loop
root.mainloop()
