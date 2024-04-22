import tkinter as tk
from tkinter import filedialog
import psutil
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from hashlib import sha256
from Crypto.Util.number import bytes_to_long

# Create main Tkinter window
root = tk.Tk()
root.geometry("500x300")
root.title("Document Signing and Encryption")

# Create a frame in the root window
frame = tk.Frame(root)
frame.pack(anchor='center')

# Function to check if a pendrive is connected
def check_pendrive():
    key_file_found = False
    for device in psutil.disk_partitions():
        if 'removable' in device.opts:
            pendrive_path = device.mountpoint
            for file in os.listdir(pendrive_path):
                if file.endswith(".key"):
                    key_file_found = True
                    break
            break
    sign_button.config(state=tk.NORMAL if key_file_found else tk.DISABLED)
    # Schedule the function to run again after 1 second
    root.after(1000, check_pendrive)


# Define a function to open a file dialog
def open_file_dialog(callback):
    file_path = filedialog.askopenfilename()
    print(f"Selected file: {file_path}")
    callback(file_path)


def open_file(entry):
    file_path = filedialog.askopenfilename()
    entry.delete(0, tk.END)
    entry.insert(0, file_path)


def open_new_window_sign_document():
    root.destroy()
    new_window = tk.Tk()
    new_window.geometry("500x300")
    new_window.title("Sign Document")

    detected_label = tk.Label(new_window, text="Detected USB with key file")
    detected_label.pack(pady=10)

    pin_label = tk.Label(new_window, text="Enter your PIN:")
    pin_label.pack(pady=10)

    pin_entry = tk.Entry(new_window, show="*")
    pin_entry.pack(pady=5)

    sign_button = tk.Button(new_window, text="Enter PIN", command=lambda: sign_document(pin_entry.get()))
    sign_button.pack(pady=10)

    new_window.mainloop()


def open_new_window_verify_signature():
    root.destroy()
    new_window = tk.Tk()
    new_window.geometry("500x300")
    new_window.title("Verify Signature")

    key_label = tk.Label(new_window, text="Public key file")
    key_entry = tk.Entry(new_window)
    key_button = tk.Button(new_window, text="Browse", command=lambda: open_file(key_entry))

    xml_label = tk.Label(new_window, text="Signature xml file")
    xml_entry = tk.Entry(new_window)
    xml_button = tk.Button(new_window, text="Browse", command=lambda: open_file(xml_entry))

    key_entry = tk.Entry(new_window, width=70)
    xml_entry = tk.Entry(new_window, width=70)

    key_label.pack(pady=10)
    key_entry.pack(pady=10)
    key_button.pack(pady=10)

    xml_label.pack(pady=10)
    xml_entry.pack(pady=10)
    xml_button.pack(pady=10)

    verify_button = tk.Button(new_window, text="Verify", command=lambda: verify(key_entry.get(), xml_entry.get()))
    verify_button.pack(pady=10)

    new_window.mainloop()


def encrypt(file_path):
    
    print(f"Encrypting file: {file_path}")

def sign_document(file_path):
    print(f"Signing file: {file_path}")



def decrypt(file_path):
    print(f"Decrypting file: {file_path}")


def verify(key_path, xml_path):
    print(f"Verifying with key: {key_path} and xml: {xml_path}")




# Create buttons
sign_button = tk.Button(frame, text="Sign document", state=tk.DISABLED, command=open_new_window_sign_document)
verify_button = tk.Button(frame, text="Verify signature", command=open_new_window_verify_signature)
encrypt_button = tk.Button(frame, text="Encrypt", command=lambda: open_file_dialog(encrypt))
decrypt_button = tk.Button(frame, text="Decrypt", command=lambda: open_file_dialog(decrypt))

# Place buttons in the frame
sign_button.pack(pady=10)
verify_button.pack(pady=10)
encrypt_button.pack(pady=10)
decrypt_button.pack(pady=10)

# Run the function to check if a pendrive is connected
check_pendrive()

# Run the Tkinter event loop
root.mainloop()