import tkinter as tk
from tkinter import filedialog
from tkinter import ttk
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

# Create a style for themed widgets
style = ttk.Style()
style.theme_use('clam')  # Choose a theme for a modern look

# Create a frame in the root window with padding
frame = tk.Frame(root, pady=20)
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
    root.withdraw()  # Hide the main window
    new_window = tk.Toplevel(root)
    new_window.geometry("500x300")
    new_window.title("Sign Document")

    detected_label = tk.Label(new_window, text="Detected USB with key file")
    detected_label.pack(pady=10)

    pin_label = tk.Label(new_window, text="Enter your PIN:")
    pin_label.pack(pady=10)

    pin_entry = tk.Entry(new_window, show="*")
    pin_entry.pack(pady=5)

    button_frame = tk.Frame(new_window)
    button_frame.pack(pady=10)

    sign_button = ttk.Button(button_frame, text="Enter PIN", command=lambda: sign_document(pin_entry.get()))
    sign_button.grid(row=0, column=0, padx=5)

    back_button = ttk.Button(button_frame, text="Back", command=lambda: back_to_main(root, new_window))
    back_button.grid(row=0, column=1, padx=5)

# Define a function to close the current window and open a new one
def open_new_window_verify_signature():
    root.withdraw()  # Hide the main window
    new_window = tk.Toplevel(root)
    new_window.geometry("500x130")
    new_window.title("Verify Signature")

    key_label = tk.Label(new_window, text="Public key file")
    key_entry = ttk.Entry(new_window, width=50)  # Adjust width
    key_button = ttk.Button(new_window, text="...", width=5, command=lambda: open_file(key_entry))

    xml_label = tk.Label(new_window, text="Signature xml file")
    xml_entry = ttk.Entry(new_window, width=50)  # Adjust width
    xml_button = ttk.Button(new_window, text="...", width=5, command=lambda: open_file(xml_entry))

    key_label.grid(row=0, column=0, pady=5, padx=5)  # Add padding
    key_entry.grid(row=0, column=1, pady=5, padx=5)  # Add padding
    key_button.grid(row=0, column=2, pady=5, padx=5)  # Add padding

    xml_label.grid(row=1, column=0, pady=5, padx=5)  # Add padding
    xml_entry.grid(row=1, column=1, pady=5, padx=5)  # Add padding
    xml_button.grid(row=1, column=2, pady=5, padx=5)  # Add padding

    # Create a frame to contain the buttons
    button_frame = tk.Frame(new_window)
    button_frame.grid(row=2, columnspan=3, pady=10)

    verify_button = ttk.Button(button_frame, text="Verify", command=lambda: verify(key_entry.get(), xml_entry.get()))
    verify_button.grid(row=0, column=0, padx=5)

    # Create a button to go back to the main window
    back_button = ttk.Button(button_frame, text="Back", command=lambda: back_to_main(root, new_window))
    back_button.grid(row=0, column=1, padx=5)

def back_to_main(root, window):
    window.destroy()  # Destroy the new window
    root.deiconify()  # Show the main window again

def encrypt(file_path):
    print(f"Encrypting file: {file_path}")

def sign_document(file_path):
    print(f"Signing file: {file_path}")

def decrypt(file_path):
    print(f"Decrypting file: {file_path}")

def verify(key_path, xml_path):
    print(f"Verifying with key: {key_path} and xml: {xml_path}")

# Create buttons with themed style
sign_button = ttk.Button(frame, text="Sign document", state=tk.DISABLED, style='Accent.TButton', command=open_new_window_sign_document)
verify_button = ttk.Button(frame, text="Verify signature", style='Accent.TButton', command=open_new_window_verify_signature)
encrypt_button = ttk.Button(frame, text="Encrypt", style='Accent.TButton', command=lambda: open_file_dialog(encrypt))
decrypt_button = ttk.Button(frame, text="Decrypt", style='Accent.TButton', command=lambda: open_file_dialog(decrypt))

# Place buttons in the frame with padding
sign_button.pack(pady=10)
verify_button.pack(pady=10)
encrypt_button.pack(pady=10)
decrypt_button.pack(pady=10)

# Run the Tkinter event loop
root.mainloop()
