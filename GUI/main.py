import tkinter as tk
from tkinter import filedialog
import os

# Function to open a file dialog and select a document
def select_document():
    file_path = filedialog.askopenfilename(filetypes=[("PDF files", "*.pdf"), ("C++ files", "*.cpp")])
    if file_path:
        label.config(text="Selected Document: " + os.path.basename(file_path))
        # You can add further functionality here, like signing the document or applying encryption/decryption

# Function to perform encryption
def encrypt_file():
    # Placeholder for encryption functionality
    pass

# Function to perform decryption
def decrypt_file():
    # Placeholder for decryption functionality
    pass

# Create main Tkinter window
root = tk.Tk()
root.title("Document Signing and Encryption")

# Create a label to display selected document
label = tk.Label(root, text="No document selected")
label.pack(pady=10)

# Create buttons for document selection, encryption, and decryption
select_button = tk.Button(root, text="Select Document", command=select_document)
select_button.pack(pady=5)

encrypt_button = tk.Button(root, text="Encrypt Document", command=encrypt_file)
encrypt_button.pack(pady=5)

decrypt_button = tk.Button(root, text="Decrypt Document", command=decrypt_file)
decrypt_button.pack(pady=5)

# Run the Tkinter event loop
root.mainloop()
