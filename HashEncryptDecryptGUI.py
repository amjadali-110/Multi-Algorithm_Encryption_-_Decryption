from tkinter import Tk, Label, Entry, Button, Text, END, messagebox

import base64
import hashlib

class HashEncryptDecryptGUI:
    def __init__(self, master):
        self.master = master
        master.title("Hash Encrypt/Decrypt")

        self.entry_label = Label(master, text="Enter text:")
        self.entry_label.grid(row=0, column=0, pady=(10, 5), padx=10, sticky='w')

        self.entry = Entry(master, width=30, font=('Arial', 10), justify='left')
        self.entry.insert(0, "Type your text here")
        self.entry.grid(row=1, column=0, pady=(0, 10), padx=10, sticky='w')

        self.encrypt_button = Button(master, text="Encrypt", command=self.encrypt)
        self.encrypt_button.grid(row=2, column=0, pady=(0, 10), padx=10, sticky='w')

        self.decrypt_button = Button(master, text="Decrypt", command=self.decrypt)
        self.decrypt_button.grid(row=2, column=1, pady=(0, 10), padx=10, sticky='w')

        self.result_label = Label(master, text="Results:")
        self.result_label.grid(row=3, column=0, pady=(0, 5), padx=10, sticky='w')

        self.base64_result_label = Label(master, text="Base64:")
        self.base64_result_label.grid(row=4, column=0, padx=10, sticky='w')
        self.base64_copy_button = Button(master, text="Copy", command=lambda: self.copy_to_clipboard(self.base64_result_label))
        self.base64_copy_button.grid(row=4, column=1, pady=(0, 5), padx=10, sticky='w')

        self.sha256_result_label = Label(master, text="SHA256:")
        self.sha256_result_label.grid(row=5, column=0, padx=10, sticky='w')
        self.sha256_copy_button = Button(master, text="Copy", command=lambda: self.copy_to_clipboard(self.sha256_result_label))
        self.sha256_copy_button.grid(row=5, column=1, pady=(0, 5), padx=10, sticky='w')

        self.md5_result_label = Label(master, text="MD5:")
        self.md5_result_label.grid(row=6, column=0, padx=10, sticky='w')
        self.md5_copy_button = Button(master, text="Copy", command=lambda: self.copy_to_clipboard(self.md5_result_label))
        self.md5_copy_button.grid(row=6, column=1, pady=(0, 5), padx=10, sticky='w')

        self.info_label = Label(master, text="Note: Decryption is not supported for SHA256 and MD5.")
        self.info_label.grid(row=7, column=0, pady=(10, 0), padx=10, sticky='w', columnspan=2)

    def encrypt(self):
        plaintext = self.entry.get()
        base64_encrypted = base64.b64encode(plaintext.encode()).decode()
        sha256_hash = hashlib.sha256(plaintext.encode()).hexdigest()
        md5_hash = hashlib.md5(plaintext.encode()).hexdigest()

        self.base64_result_label.config(text=f"Base64: {base64_encrypted}")
        self.sha256_result_label.config(text=f"SHA256: {sha256_hash}")
        self.md5_result_label.config(text=f"MD5: {md5_hash}")

    def decrypt(self):
        base64_encrypted = self.base64_result_label.cget("text").split(": ")[1]
        sha256_hash = self.sha256_result_label.cget("text").split(": ")[1]
        md5_hash = self.md5_result_label.cget("text").split(": ")[1]

        base64_decrypted = base64.b64decode(base64_encrypted).decode()
        sha256_decrypted = "Decryption not supported for SHA256"
        md5_decrypted = "Decryption not supported for MD5"

        self.base64_result_label.config(text=f"Base64 Decrypted: {base64_decrypted}")
        self.sha256_result_label.config(text=f"SHA256 Decrypted: {sha256_decrypted}")
        self.md5_result_label.config(text=f"MD5 Decrypted: {md5_decrypted}")

    def copy_to_clipboard(self, label):
        result_text = label.cget("text").split(": ")[1]
        self.master.clipboard_clear()
        self.master.clipboard_append(result_text)
        self.master.update()
        messagebox.showinfo("Copy to Clipboard", f"{label.cget('text').split(': ')[0]} copied to clipboard!")

if __name__ == '__main__':
    root = Tk()
    app = HashEncryptDecryptGUI(root)
    root.mainloop()
