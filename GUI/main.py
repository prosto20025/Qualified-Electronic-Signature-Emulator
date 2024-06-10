import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
import psutil
import os

from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import unpad
from tkinter import messagebox
from datetime import datetime
import xml.etree.ElementTree as ET

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
    def open_signing_window(private_key_path, pin):
        try:
            # Decrypt the private key
            private_key = decrypt_private_key(private_key_path, pin)
        except IncorrectPINError:
            messagebox.showerror("Error", "Incorrect PIN provided.")
            return

        root.withdraw()  # Hide the main window
        signing_window = tk.Toplevel(root)
        signing_window.geometry("500x300")
        signing_window.title("Sign Document")

        key_info_label = tk.Label(signing_window, text="RSA Private Key: " + private_key_path)
        key_info_label.pack(pady=10)

        detected_label = tk.Label(signing_window, text="Key decryption was successful.")
        detected_label.pack(pady=10)

        file_label = tk.Label(signing_window, text="Select document to sign:")
        file_label.pack(pady=10)

        def open_file(entry):
            file_path = filedialog.askopenfilename()
            entry.delete(0, tk.END)
            entry.insert(0, file_path)

        file_entry = ttk.Entry(signing_window, width=50)
        file_entry.pack(pady=5)
        file_button = ttk.Button(signing_window, text="...", width=5, command=lambda: open_file(file_entry))
        file_button.pack(pady=5)

        button_frame = tk.Frame(signing_window)
        button_frame.pack(pady=10)

        def sign_document(private_key_path, file_to_sign, xml_file_path):
            try:
                # Load the private key
                with open(private_key_path, 'rb') as key_file:
                    private_key = RSA.import_key(key_file.read())

                # Open the selected file
                with open(file_to_sign, 'rb') as f:
                    file_data = f.read()

                # Calculate the hash of the document
                doc_hash = hashlib.sha256(file_data).digest()

                # Generate the timestamp for the signature
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                # Sign the document hash using PKCS1_v1_5
                signature = pkcs1_15.new(private_key).sign(SHA256.new(doc_hash))
                signature_hex = signature.hex()

                # Create XML signature file
                create_xml_signature(file_to_sign, doc_hash, signature_hex, timestamp, xml_file_path)

                print("Document signed successfully.")

            except Exception as e:
                print(f"Error: {str(e)}")

    root.withdraw()  # Hide the main window
    new_window = tk.Toplevel(root)
    new_window.geometry("500x300")
    new_window.title("Sign Document")

    key_label = tk.Label(new_window, text="Select RSA private key file:")
    key_label.pack(pady=10)

    key_entry = ttk.Entry(new_window, width=50)
    key_entry.pack(pady=5)

    key_button = ttk.Button(new_window, text="...", width=5, command=lambda: open_file(key_entry))
    key_button.pack(pady=5)

    pin_label = tk.Label(new_window, text="Enter your PIN:")
    pin_label.pack(pady=10)

    pin_entry = ttk.Entry(new_window, show="*")
    pin_entry.pack(pady=5)

    button_frame = tk.Frame(new_window)
    button_frame.pack(pady=10)

    sign_button = ttk.Button(button_frame, text="Next", command=lambda: open_signing_window(key_entry.get(), pin_entry.get()))
    sign_button.grid(row=0, column=0, padx=5)

    back_button = ttk.Button(button_frame, text="Back", command=new_window.destroy)
    back_button.grid(row=0, column=1, padx=5)



# Define a function to close the current window and open a new one
def open_new_window_verify_signature():
    root.withdraw()  # Hide the main window
    new_window = tk.Toplevel(root)
    new_window.geometry("600x200")
    new_window.title("Verify Signature")

    key_label = tk.Label(new_window, text="Public key file")
    key_entry = ttk.Entry(new_window, width=50)
    key_button = ttk.Button(new_window, text="...", width=5, command=lambda: open_file(key_entry))

    xml_label = tk.Label(new_window, text="Signature xml file")
    xml_entry = ttk.Entry(new_window, width=50)
    xml_button = ttk.Button(new_window, text="...", width=5, command=lambda: open_file(xml_entry))

    doc_label = tk.Label(new_window, text="Document file")
    doc_entry = ttk.Entry(new_window, width=50)
    doc_button = ttk.Button(new_window, text="...", width=5, command=lambda: open_file(doc_entry))

    key_label.grid(row=0, column=0, pady=5, padx=5)
    key_entry.grid(row=0, column=1, pady=5, padx=5)
    key_button.grid(row=0, column=2, pady=5, padx=5)

    xml_label.grid(row=1, column=0, pady=5, padx=5)
    xml_entry.grid(row=1, column=1, pady=5, padx=5)
    xml_button.grid(row=1, column=2, pady=5, padx=5)

    doc_label.grid(row=2, column=0, pady=5, padx=5)
    doc_entry.grid(row=2, column=1, pady=5, padx=5)
    doc_button.grid(row=2, column=2, pady=5, padx=5)

    button_frame = tk.Frame(new_window)
    button_frame.grid(row=3, column=0, columnspan=3, pady=10, padx=5)

    def verify(public_key_path, xml_file_path, document_path):
        verify_signature(public_key_path, xml_file_path, document_path)

    verify_button = ttk.Button(button_frame, text="Verify", command=lambda: verify(key_entry.get(), xml_entry.get(), doc_entry.get()))
    verify_button.grid(row=0, column=0, padx=5)

    # Create a button to go back to the main window
    back_button = ttk.Button(button_frame, text="Back", command=lambda: back_to_main(root, new_window))
    back_button.grid(row=0, column=1, padx=5)



def back_to_main(root, window):
    window.destroy()  # Destroy the new window
    root.deiconify()  # Show the main window again

def open_new_window_encrypt_file():
    root.withdraw()  # Hide the main window
    new_window = tk.Toplevel(root)
    new_window.geometry("500x300")
    new_window.title("Encrypt File")

    file_label = tk.Label(new_window, text="Select file to encrypt:")
    file_label.pack(pady=10)

    file_entry = ttk.Entry(new_window, width=50)
    file_entry.pack(pady=5)
    file_button = ttk.Button(new_window, text="...", width=5, command=lambda: open_file(file_entry))
    file_button.pack(pady=5)

    key_label = tk.Label(new_window, text="Select RSA public key file:")
    key_label.pack(pady=10)

    key_entry = ttk.Entry(new_window, width=50)
    key_entry.pack(pady=5)
    key_button = ttk.Button(new_window, text="...", width=5, command=lambda: open_file(key_entry))
    key_button.pack(pady=5)

    button_frame = tk.Frame(new_window)
    button_frame.pack(pady=10)

    encrypt_button = ttk.Button(button_frame, text="Encrypt", command=lambda: encrypt_file(file_entry.get(), key_entry.get()))
    encrypt_button.grid(row=0, column=0, padx=5)

    back_button = ttk.Button(button_frame, text="Back", command=lambda: back_to_main(root, new_window))
    back_button.grid(row=0, column=1, padx=5)


def encrypt_file(file_path, key_path):
    try:
        # Read the file data
        with open(file_path, 'rb') as f:
            file_data = f.read()

        # Generate a random AES key
        aes_key = get_random_bytes(32)  # AES-256

        # Encrypt the file data with AES
        cipher_aes = AES.new(aes_key, AES.MODE_CBC)
        iv = cipher_aes.iv
        encrypted_data = iv + cipher_aes.encrypt(pad(file_data, AES.block_size))

        # Read the public key
        with open(key_path, 'rb') as k:
            key = k.read()

        public_key = RSA.import_key(key)
        cipher_rsa = PKCS1_OAEP.new(public_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)

        # Save the encrypted AES key and the encrypted file data
        encrypted_file_path = file_path + '.enc'
        with open(encrypted_file_path, 'wb') as ef:
            ef.write(encrypted_aes_key + encrypted_data)

        messagebox.showinfo("Success", "File encrypted successfully.")

    except Exception as e:
        messagebox.showerror("Error", str(e))


def create_xml_signature(file_to_sign, doc_hash, signature_hex, timestamp, xml_file_path):
    import xml.etree.ElementTree as ET
    from xml.dom import minidom

    # Create XML structure
    signature = ET.Element('Signature')

    doc_info = ET.SubElement(signature, 'DocumentInformation')
    ET.SubElement(doc_info, 'FileName').text = os.path.basename(file_to_sign)
    ET.SubElement(doc_info, 'FileSize').text = str(os.path.getsize(file_to_sign))
    ET.SubElement(doc_info, 'FileExtension').text = os.path.splitext(file_to_sign)[1]
    ET.SubElement(doc_info, 'LastModified').text = str(datetime.fromtimestamp(os.path.getmtime(file_to_sign)))
    ET.SubElement(doc_info, 'Timestamp').text = timestamp

    signer_info = ET.SubElement(signature, 'SignerInformation')
    ET.SubElement(signer_info, 'Name').text = "User A"
    ET.SubElement(signer_info, 'Timestamp').text = timestamp

    ET.SubElement(signature, 'SignatureValue').text = signature_hex

    # Prettify the XML output
    xml_str = minidom.parseString(ET.tostring(signature)).toprettyxml(indent="   ")

    # Write to file
    with open(xml_file_path, 'w') as xml_file:
        xml_file.write(xml_str)
class IncorrectPINError(Exception):
    pass
def decrypt_private_key(encrypted_key_path, user_pin):
    try:
        # Read the encrypted private key
        with open(encrypted_key_path, 'rb') as k:
            encrypted_private_key = k.read()

        # Hash the user PIN
        pin_hashed = hashlib.sha3_256()
        pin_hashed.update(user_pin.encode())
        pin_hashed = pin_hashed.digest()

        # Extract the IV and the encrypted key data
        iv = encrypted_private_key[:AES.block_size]
        encrypted_key_data = encrypted_private_key[AES.block_size:]

        # Decrypt the private key
        cipher_aes = AES.new(pin_hashed, AES.MODE_CBC, iv)


        # Check if the decrypted key is valid
        try:
            private_key_pem = unpad(cipher_aes.decrypt(encrypted_key_data), AES.block_size)
            RSA.import_key(private_key_pem)
        except ValueError:
            # If the decrypted key is invalid, raise an error
            raise IncorrectPINError("Incorrect PIN provided.")

        return RSA.import_key(private_key_pem)
    except Exception as e:
        raise e


def decrypt_file(encrypted_file_path, encrypted_key_path, user_pin):
    try:
        # Decrypt the private key
        private_key = decrypt_private_key(encrypted_key_path, user_pin)

        # Check if private key is None (indicating incorrect PIN)
        if private_key is None:
            messagebox.showerror("Error", "Incorrect PIN provided.")
            return

        # Continue decryption process
        cipher_rsa = PKCS1_OAEP.new(private_key)

        # Read the encrypted file data
        with open(encrypted_file_path, 'rb') as ef:
            encrypted_file_data = ef.read()

        # Extract the encrypted AES key and the encrypted data
        rsa_key_size = len(cipher_rsa._key.n.to_bytes((cipher_rsa._key.n.bit_length() + 7) // 8, 'big'))
        encrypted_aes_key = encrypted_file_data[:rsa_key_size]
        encrypted_data = encrypted_file_data[rsa_key_size:]

        # Decrypt the AES key
        aes_key = cipher_rsa.decrypt(encrypted_aes_key)

        # Extract the IV and the actual encrypted file data
        iv = encrypted_data[:AES.block_size]
        encrypted_file_data = encrypted_data[AES.block_size:]

        # Decrypt the file data with AES
        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
        file_data = unpad(cipher_aes.decrypt(encrypted_file_data), AES.block_size)

        # Generate the output file path without the encryption extension
        folder_path, file_name = os.path.split(encrypted_file_path)
        file_name_without_extension = os.path.splitext(file_name)[0]
        output_file_name = "decrypted_" + file_name_without_extension
        output_file_path = os.path.join(folder_path, output_file_name)

        # Write the decrypted file data to the output file
        with open(output_file_path, 'wb') as of:
            of.write(file_data)

        messagebox.showinfo("Success", "File decrypted successfully. Saved as " + output_file_name)

    except Exception as e:
        messagebox.showerror("Error", str(e))


def open_new_window_decrypt_file():
    root.withdraw()  # Hide the main window
    new_window = tk.Toplevel(root)
    new_window.geometry("500x300")
    new_window.title("Decrypt File")

    def open_file(entry):
        file_path = filedialog.askopenfilename()
        entry.delete(0, tk.END)
        entry.insert(0, file_path)

    def decrypt_file_func():
        encrypted_file_path = file_entry.get()
        key_path = key_entry.get()
        user_pin = pin_entry.get()

        if not os.path.exists(encrypted_file_path) or not os.path.isfile(encrypted_file_path):
            messagebox.showerror("Error", "Invalid encrypted file path.")
            return

        if not os.path.exists(key_path) or not os.path.isfile(key_path):
            messagebox.showerror("Error", "Invalid RSA private key file path.")
            return

        if not user_pin:
            messagebox.showerror("Error", "Please enter your PIN.")
            return

        try:
            decrypt_file(encrypted_file_path, key_path, user_pin)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    file_label = tk.Label(new_window, text="Select encrypted file:")
    file_label.pack(pady=10)

    file_entry = ttk.Entry(new_window, width=50)
    file_entry.pack(pady=5)
    file_button = ttk.Button(new_window, text="...", width=5, command=lambda: open_file(file_entry))
    file_button.pack(pady=5)

    key_label = tk.Label(new_window, text="Select RSA private key file:")
    key_label.pack(pady=10)

    key_entry = ttk.Entry(new_window, width=50)
    key_entry.pack(pady=5)
    key_button = ttk.Button(new_window, text="...", width=5, command=lambda: open_file(key_entry))
    key_button.pack(pady=5)

    pin_label = tk.Label(new_window, text="Enter your PIN:")
    pin_label.pack(pady=10)

    pin_entry = ttk.Entry(new_window, show="*", width=20)
    pin_entry.pack(pady=5)

    button_frame = tk.Frame(new_window)
    button_frame.pack(pady=10)

    decrypt_button = ttk.Button(button_frame, text="Decrypt", command=decrypt_file_func)
    decrypt_button.grid(row=0, column=0, padx=5)

    back_button = ttk.Button(button_frame, text="Back", command=lambda: back_to_main(root, new_window))
    back_button.grid(row=0, column=1, padx=5)

import os
import hashlib
import xml.etree.ElementTree as ET
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from tkinter import messagebox
import tkinter as tk
from tkinter import ttk


def verify_signature(public_key_path, xml_file_path, document_path):
    try:
        # Load the public key
        with open(public_key_path, 'rb') as key_file:
            public_key = RSA.import_key(key_file.read())

        # Check if the XML file exists
        if not os.path.exists(xml_file_path):
            messagebox.showerror("Error", "XML file does not exist.")
            return

        # Parse the XML file to extract the signature value
        tree = ET.parse(xml_file_path)
        root = tree.getroot()
        signature_hex = root.find('.//SignatureValue').text
        if signature_hex is None:
            messagebox.showerror("Error", "Signature value not found in the XML.")
            return

        # Convert the signature from hex string to bytes
        signature_value = bytes.fromhex(signature_hex)

        # Open the document and read its contents
        if not os.path.exists(document_path):
            messagebox.showerror("Error", "Document file does not exist.")
            return

        with open(document_path, 'rb') as doc_file:
            document_data = doc_file.read()

        # Calculate the hash of the document
        h = SHA256.new(document_data)

        # Verify the signature
        try:
            pkcs1_15.new(public_key).verify(h, signature_value)
            messagebox.showinfo("Success", "Signature is valid.")
        except (ValueError, TypeError) as e:
            messagebox.showerror("Error", f"Signature is not valid: {str(e)}")

    except FileNotFoundError:
        messagebox.showerror("Error", "File not found.")
    except Exception as e:
        messagebox.showerror("Error", str(e))


# Create buttons with themed style
sign_button = ttk.Button(frame, text="Sign document", style='Accent.TButton', command=open_new_window_sign_document)
verify_button = ttk.Button(frame, text="Verify signature", style='Accent.TButton', command=open_new_window_verify_signature)
encrypt_button = ttk.Button(frame, text="Encrypt", style='Accent.TButton', command=open_new_window_encrypt_file)
decrypt_button = ttk.Button(frame, text="Decrypt", style='Accent.TButton', command=open_new_window_decrypt_file)

# Place buttons in the frame with padding
sign_button.pack(pady=10)
verify_button.pack(pady=10)
encrypt_button.pack(pady=10)
decrypt_button.pack(pady=10)

# Run the Tkinter event loop
root.mainloop()
