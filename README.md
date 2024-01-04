# Hash Encrypt/Decrypt GUI
This simple GUI application allows you to encrypt and decrypt text using Base64 encoding, SHA256 hash, and MD5 hash. It provides a user-friendly interface for performing these operations.

## How to Use
Run the application by executing the HashEncryptDecryptGUI.py file.
Enter the text you want to encrypt in the provided entry field.
Click the "Encrypt" button to generate Base64 encoding, SHA256 hash, and MD5 hash for the entered text.
To copy the results to the clipboard, click the "Copy" button next to each result label.
Note: Decryption is not supported for SHA256 and MD5.

## Dependencies
This application uses the following Python libraries:
* tkinter: GUI toolkit for creating the graphical user interface.
* base64: Provides base64 encoding and decoding functions.
* hashlib: Allows the use of various hash functions such as SHA256 and MD5.

## Usage Example
```
from tkinter import Tk
from HashEncryptDecryptGUI import HashEncryptDecryptGUI

if __name__ == '__main__':
    root = Tk()
    app = HashEncryptDecryptGUI(root)
    root.mainloop()
```
## Important Note
Decryption is not supported for SHA256 and MD5. Attempting to decrypt these hashes will display a message indicating that decryption is not supported.
Feel free to explore and use this simple Hash Encrypt/Decrypt GUI for your text encryption needs!
