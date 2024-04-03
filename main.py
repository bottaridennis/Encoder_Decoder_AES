import tkinter as tk
from tkinter import filedialog
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def generate_key():
    return get_random_bytes(16)

def get_key_from_user():
    key_hex = key_entry.get()
    try:
        key = bytes.fromhex(key_hex)
        if len(key) != 16:
            raise ValueError("Key must be 16 bytes long.")
        return key
    except ValueError as e:
        result_label.config(text="Invalid key format")
        return None

def get_input_file():
    input_file = filedialog.askopenfilename()
    input_entry.delete(0, tk.END)
    input_entry.insert(0, input_file)

def get_output_file():
    output_file = filedialog.asksaveasfilename()
    output_entry.delete(0, tk.END)
    output_entry.insert(0, output_file)

def encrypt():
    input_file = input_entry.get()
    output_file = output_entry.get() or input_file
    key = get_key_from_user()
    if key:
        encrypt_file(input_file, output_file, key)

def decrypt():
    input_file = input_entry.get()
    output_file = output_entry.get() or input_file
    key = get_key_from_user()
    if key:
        decrypt_file(input_file, output_file, key)

def encrypt_file(input_file, output_file, key):
    try:
        with open(input_file, 'rb') as f_in:
            data = f_in.read()
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        with open(output_file, 'wb') as f_out:
            f_out.write(cipher.nonce)
            f_out.write(tag)
            f_out.write(ciphertext)
        result_label.config(text="File encrypted successfully.")
    except Exception as e:
        result_label.config(text="Encryption failed: " + str(e))

def decrypt_file(input_file, output_file, key):
    try:
        with open(input_file, 'rb') as f_in:
            nonce = f_in.read(16)
            tag = f_in.read(16)
            ciphertext = f_in.read()
        cipher = AES.new(key, AES.MODE_EAX, nonce)
        data = cipher.decrypt_and_verify(ciphertext, tag)
        with open(output_file, 'wb') as f_out:
            f_out.write(data)
        result_label.config(text="File decrypted successfully.")
    except Exception as e:
        result_label.config(text="Decryption failed: " + str(e))

# Setup GUI
root = tk.Tk()
root.title("Crypter")

frame = tk.Frame(root)
frame.pack(padx=20, pady=20)

input_label = tk.Label(frame, text="Input File:")
input_label.grid(row=0, column=0, sticky="w")

input_entry = tk.Entry(frame, width=50)
input_entry.grid(row=0, column=1, padx=10, pady=5)

input_button = tk.Button(frame, text="Browse", command=get_input_file)
input_button.grid(row=0, column=2)

output_label = tk.Label(frame, text="Output File:")
output_label.grid(row=1, column=0, sticky="w")

output_entry = tk.Entry(frame, width=50)
output_entry.grid(row=1, column=1, padx=10, pady=5)

output_button = tk.Button(frame, text="Browse", command=get_output_file)
output_button.grid(row=1, column=2)

key_label = tk.Label(frame, text="Key:")
key_label.grid(row=2, column=0, sticky="w")

key_entry = tk.Entry(frame, width=50)
key_entry.grid(row=2, column=1, padx=10, pady=5)

encrypt_button = tk.Button(frame, text="Encrypt", command=encrypt)
encrypt_button.grid(row=3, column=0, pady=10)

decrypt_button = tk.Button(frame, text="Decrypt", command=decrypt)
decrypt_button.grid(row=3, column=1, pady=10)

result_label = tk.Label(frame, text="", fg="green")
result_label.grid(row=4, columnspan=3)

root.geometry("600x250")  # Imposta la dimensione della finestra principale
root.mainloop()
