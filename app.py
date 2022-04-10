# pip install pycryptodome, pyperclip, binascii, tkinter

import binascii
import time
import tkinter as tk
from tkinter import *

import pyperclip
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


class crypt:

    def __init__(self, encrypted, decrypted, password, nonce, time):
        self.enc = encrypted
        self.dec = decrypted
        self.nc = nonce
        self.time = time

    # def set(self, encrypted, decrypted, password, nonce):
    #    self.enc = encrypted
    #    self.dec = decrypted
    #    self.paswd = password
    #    self.nc = nonce

    def clear(self):
        self.enc = ""
        self.dec = ""
        self.paswd = ""
        self.nc = ""


def to_print(txtbox, to_print):
    txtbox['state'] = "normal"
    txtbox.delete('1.0', 'end')
    txtbox.insert('end', to_print)
    txtbox['state'] = "disabled"

# functions


def encrypt(src, key):                                      # Encryption Function starts here
    # creating objects of AES class in CTR mode
    AES_obj = AES.new(key, AES.MODE_CTR)
    # encrypting and storing the ciphered data
    ciphered_data = AES_obj.encrypt(src)

    # returning the ciphered data as well as the nonce value
    return ciphered_data, AES_obj.nonce


def decrypt(src, key, nonce):                               # Decryption Function starts here
    # creating objects of AES class in CTR mode
    AES_obj = AES.new(key, AES.MODE_CTR, nonce=nonce)
    # decrypting and storing the ciphered data
    decrypted_data = AES_obj.decrypt(src)

    # returning the deciphered data
    return decrypted_data


def enc_str(myobj, src, key):
    # converting the key from string to bytes object
    key = bytes(key.rstrip("\n"), 'utf-8')
    # Obtaining the Padded Key, with length in the multiple of block_size i.e. 16 bytes
    key = pad(key, AES.block_size)

    # formatting input(s)
    # To accept the source data for encryption we need to format it to utf-8
    src = bytes(src.rstrip("\n"), 'utf-8')

    # Encryption process starts here
    start = time.time()
    ciphered_data, nonce = encrypt(src, key)
    # Encryption process ends here
    myobj.time = str(time.time() - start) + " seconds"

    # formatting output(s)
    # formatting the ciphered data from binary to ascii
    ciphered_data = str(binascii.hexlify(ciphered_data))
    # formatting the nonce value from binary to ascii
    nonce = str(binascii.hexlify(nonce))

    myobj.enc = str(ciphered_data[2:-1])
    myobj.nc = str(nonce[2:-1])


def dec_str(myobj, src, key, nonce):
    # converting the key to bytes object
    key = bytes(key.rstrip("\n"), 'utf-8')
    # This is the Padded Key, with length in the multiple of block_size
    key = pad(key, AES.block_size)

    # formatting input(s)
    # formatting the ciphered data from ascii to binary
    src = binascii.unhexlify(src.rstrip("\n"))
    # formatting the nonce value from ascii to binary
    nonce = binascii.unhexlify(nonce.rstrip("\n"))

    # Decryption process starts here
    start = time.time()
    deciphered_data = decrypt(src, key, nonce)
    myobj.time = str(time.time() - start) + " seconds"

    # formatting output(s)
    # formatting the deciphered data to binary to ascii
    deciphered_data = deciphered_data.decode('ascii')

    # printing the output(s)
    myobj.dec = deciphered_data


def print_status(status, msg):
    status['text'] = msg


def destroy_all(frame):
    for item in frame.winfo_children():
        item.destroy()


def construct_enc_window(enc_frame, status):
    # Plaintext header
    header1 = Label(enc_frame, text="Enter text to encrypt :\n*****************",
                    font=("Unifont", 14))
    header1.place(relx=0.27, rely=0.037, anchor="center")

    # Plaintext box
    plaintext = tk.Text(enc_frame, width=50, height=12, font=(
        "Unifont", 10), foreground="black")
    plaintext.grid(padx=20, pady=(50, 10))

    # Password header
    header2 = Label(enc_frame, text="Enter Password :", font=("Unifont", 14))
    header2.place(relx=0.2, rely=0.50, anchor="center")

    # Enter password box
    password = tk.Text(enc_frame, width=19, height=1.2, font=(
        "Unifont", 14), foreground="black")
    password.grid(padx=(182, 20), pady=10)

    # Copy password button
    paswdbt = Button(enc_frame, text="copy password", font=(
        "Unifont", 10), bg="grey", fg="black", width=13, height=1, command=lambda: [pyperclip.copy(password.get('1.0', 'end').rstrip('\n'))])
    paswdbt.place(relx=0.875, rely=0.50, anchor="center")

    # Encrypt button
    encryptbt = Button(enc_frame, text="ENCR\n-YPT", font=(
        "Unifont", 20), bg="black", fg="white", width=6, height=5, command=lambda: [myobj.clear(), enc_str(myobj, plaintext.get('1.0', 'end'), password.get('1.0', 'end')), to_print(ciphertext, "\n\nCIPHERTEXT : "+myobj.enc+"\n\nNONCE : "+myobj.nc), print_status(status, " The string has been encrypted!\nTime taken : "+myobj.time)])
    encryptbt.place(relx=0.875, rely=0.26, anchor="center")

    # Ciphertext header
    header3 = Label(enc_frame, text="Encrypted Text :\n*************",
                    font=("Unifont", 14))
    header3.place(relx=0.2, rely=0.57, anchor="center")

    # Ciphertext box
    ciphertext = tk.Text(enc_frame, state="disabled", width=50, height=10, font=(
        "Unifont", 10), foreground="black")
    ciphertext.grid(padx=20, pady=(50, 50))

    # Copy Cipher button
    cipherbt = Button(enc_frame, text="copy\nCiphertext", font=(
        "Unifont", 10), bg="grey", fg="black", width=13, height=2, command=lambda: [pyperclip.copy(myobj.enc.rstrip('\n'))])
    cipherbt.place(relx=0.875, rely=0.70, anchor="center")

    # Copy Nonce button
    noncebt = Button(enc_frame, text="copy Nonce", font=(
        "Unifont", 10), bg="grey", fg="black", width=13, height=1, command=lambda: [pyperclip.copy(myobj.nc.rstrip('\n'))])
    noncebt.place(relx=0.875, rely=0.80, anchor="center")


def construct_dec_window(dec_frame, status):

    # Paste Cipher button
    cipherbt = Button(dec_frame, text="paste\nCiphertext", font=(
        "Unifont", 10), bg="grey", fg="black", width=13, height=2, command=lambda: [to_print(ciphertext, pyperclip.paste())])
    cipherbt.place(relx=0.875, rely=0.05, anchor="center")

    # Ciphertext header
    header1 = Label(dec_frame, text="Enter text to decrypt :\n*****************",
                    font=("Unifont", 14))
    header1.place(relx=0.27, rely=0.037, anchor="center")

    # Ciphertext box
    ciphertext = tk.Text(dec_frame, width=50, height=12, font=(
        "Unifont", 10), foreground="black")
    ciphertext.grid(padx=20, pady=(50, 10))

    # Password header
    header2 = Label(dec_frame, text="Enter Password :", font=("Unifont", 14))
    header2.place(relx=0.2, rely=0.50, anchor="center")

    # Enter password box
    password = tk.Text(dec_frame, width=19, height=1.2, font=(
        "Unifont", 14), foreground="black")
    password.grid(padx=(182, 20), pady=10)

    # Nonce header
    header3 = Label(dec_frame, text="Enter Nonce :   ", font=("Unifont", 14))
    header3.place(relx=0.2, rely=0.59, anchor="center")

    # Enter Nonce box
    nonce = tk.Text(dec_frame, width=19, height=1.2, font=(
        "Unifont", 14), foreground="black")
    nonce.grid(padx=(182, 20), pady=10)

    # Decrypt button
    decryptbt = Button(dec_frame, text="DECR\n-YPT", font=(
        "Unifont", 20), bg="grey", fg="black", width=6, height=5, command=lambda: [dec_str(myobj, ciphertext.get('1.0', 'end'), password.get('1.0', 'end'), nonce.get('1.0', 'end')), to_print(plaintext, myobj.dec), print_status(status, " The string has been decrypted!\nTime taken : "+myobj.time), myobj.clear()])
    decryptbt.place(relx=0.875, rely=0.26, anchor="center")

    # Plaintext header
    header4 = Label(dec_frame, text="Decrypted Text :\n*************",
                    font=("Unifont", 14))
    header4.place(relx=0.2, rely=0.68, anchor="center")

    # Plaintext box
    plaintext = tk.Text(dec_frame, state="disabled", width=50, height=8, font=(
        "Unifont", 10), foreground="black")
    plaintext.grid(padx=20, pady=(50, 50))

    # Paste Password button
    paswdbt = Button(dec_frame, text="paste\nPassword", font=(
        "Unifont", 10), bg="grey", fg="black", width=13, height=2, command=lambda: [to_print(password, pyperclip.paste())])
    paswdbt.place(relx=0.875, rely=0.50, anchor="center")

    # Paste Nonce button
    noncebt = Button(dec_frame, text="paste Nonce", font=(
        "Unifont", 10), bg="grey", fg="black", width=13, height=1, command=lambda: [to_print(nonce, pyperclip.paste())])
    noncebt.place(relx=0.875, rely=0.60, anchor="center")


def construct_menubar(root, mainWindow, status):
    menubar = Menu(root)

    menu1 = Menu(menubar, tearoff=0)
    menu1.add_command(label="New File...", command=lambda: [])
    menu1.add_command(label="Open File...", command=lambda: [])
    menu1.add_separator()
    menu1.add_command(label="Encrypt", command=lambda: [destroy_all(mainWindow), construct_enc_window(
        mainWindow, status), print_status(status, " Time to encrypt some plaintext!")])
    menu1.add_command(label="Decrypt", command=lambda: [destroy_all(mainWindow), construct_dec_window(
        mainWindow, status), print_status(status, " Time to decrypt some ciphertext!")])
    menu1.add_separator()
    menu1.add_command(label="Exit", command=lambda: [root.quit])
    menubar.add_cascade(label="File", menu=menu1)

    menu2 = Menu(menubar, tearoff=0)
    menu2.add_command(label="ECB Mode", command=lambda: [])
    menu2.add_command(label="CBC Mode", command=lambda: [])
    menu2.add_command(label="CTR Mode", command=lambda: [])
    menu2.add_command(label="OFB Mode", command=lambda: [])
    menu2.add_command(label="CFB Mode", command=lambda: [])
    menubar.add_cascade(label="Change Mode", menu=menu2)

    menu3 = Menu(menubar, tearoff=0)
    menu3.add_command(label="Tutorial", command=lambda: [])
    menu3.add_command(label="About", command=lambda: [])
    menubar.add_cascade(label="Help", menu=menu3)

    root.config(menu=menubar)


if __name__ == '__main__':
    # Main Window
    root = Tk()
    root.title("Cryptography System")
    root.geometry("500x500")
    #root.iconbitmap('icon.ico')
    root.pack_propagate(False)
    root.resizable(0, 0)

    myobj = crypt("", "", "", "", "")

    # Main Window
    mainWindow = Frame(root)
    mainWindow.pack_propagate(False)

    # Status Bar
    status = Label(root, text=" Hello There!",
                   bd=1, relief="sunken", anchor="w")
    status.pack(side="bottom", fill="x")

    mainWindow.pack(fill="both", expand=True)

    construct_menubar(root, mainWindow, status)

    root.mainloop()
