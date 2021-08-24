# imports
from memory_profiler import profile
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
import binascii
import time
import os
import psutil


@profile
def encrypt(src, key, iv):
    padded_bytes = pad(src, AES.block_size)
    print("Current CPU utilization, before encryption is:\t" +
          str(psutil.cpu_percent(interval=1))+"%")
    AES_obj = AES.new(key, AES.MODE_CFB, iv)
    ciphered_data = AES_obj.encrypt(padded_bytes)
    print("Current CPU utilization, after encryption is:\t" +
          str(psutil.cpu_percent(interval=1))+"%")

    return ciphered_data


@profile
def decrypt(src, key, iv):
    print("Current CPU utilization, before decryption is:\t" +
          str(psutil.cpu_percent(interval=1))+"%")
    AES_obj = AES.new(key, AES.MODE_CFB, iv)
    decrypted_data = AES_obj.decrypt(src)
    decrypted_data = unpad(decrypted_data, AES.block_size)
    print("Current CPU utilization, after decryption is:\t" +
          str(psutil.cpu_percent(interval=1))+"%")

    return decrypted_data


@profile
def encrypt_file(filename, key, iv):
    with open(filename, 'rb') as fo:
        stream = fo.read()
        enc = encrypt(stream, key, iv)

    with open(filename + ".enc", 'wb') as fo:
        fo.write(enc)

    os.remove(filename)


@profile
def decrypt_file(filename, key, iv):
    with open(filename, 'rb') as fo:
        stream = fo.read()
        dec = decrypt(stream, key, iv)

    with open(filename[:-4], 'wb') as fo:
        fo.write(dec)

    os.remove(filename)


def enc_str():
    iv = str(input("Enter initialization vector:\t"))
    iv = bytes(iv, 'utf-8')
    iv = pad(iv, AES.block_size)

    key = str(input("Enter the encryption/decryption Key:\t"))
    key = bytes(key, 'utf-8')
    key = pad(key, AES.block_size)

    src = input("Enter data to encrypt:\t")
    src = bytes(src, 'utf-8')

    start = time.time()
    ciphered_data = encrypt(src, key, iv)
    enc_time = str(time.time() - start)
    ciphered_data = str(binascii.hexlify(ciphered_data))

    print('''
    CIPHERED DATA:\t'''+str(ciphered_data[2:-1])
          )
    print("\n    Total Time taken for encryption is:\t"+enc_time+" seconds")


def dec_str():
    iv = str(input("Enter initialization vector:\t"))
    iv = bytes(iv, 'utf-8')
    iv = pad(iv, AES.block_size)

    key = str(input("Enter the encryption/decryption Key:\t"))
    key = bytes(key, 'utf-8')
    key = pad(key, AES.block_size)

    src = input("Enter data to decrypt:\t")
    src = binascii.unhexlify(src)

    start = time.time()
    deciphered_data = decrypt(src, key, iv).decode('ascii')
    dec_time = str(time.time() - start)

    print("\nDECIPHERED DATA:\t"+deciphered_data)
    print("Total Time taken for encryption is:\t"+dec_time+" seconds")
    print("\n\n")


def enc_f():
    iv = str(input("Enter initialization vector:\t"))
    iv = bytes(iv, 'utf-8')
    iv = pad(iv, AES.block_size)

    key = str(input("Enter the encryption/decryption Key:\t"))
    key = bytes(key, 'utf-8')
    key = pad(key, AES.block_size)

    print("\nThese are the files in your current directory:-")
    print("********************************************************************************\n")
    os.system("dir /b")
    print("\n********************************************************************************\n")
    filename = str(
        input("Enter the NAME of the file you want to encrypt (WITH THE EXTENSION):\t"))

    start = time.time()
    encrypt_file(filename, key, iv)
    enc_time = str(time.time() - start)

    print("\n\tThe file '"+filename+"' has been ENCRYPTED, Successfully!!")
    print("\n\tTotal Time taken for encryption is:\t"+enc_time+" seconds")


def dec_f():
    iv = str(input("Enter initialization vector:\t"))
    iv = bytes(iv, 'utf-8')
    iv = pad(iv, AES.block_size)

    key = str(input("Enter the encryption/decryption Key:\t"))
    key = bytes(key, 'utf-8')
    key = pad(key, AES.block_size)

    print("\nThese are the files in your current directory:-")
    print("********************************************************************************\n")
    os.system("dir /b")
    print("\n********************************************************************************\n")
    filename = str(
        input("Enter the NAME of the file you want to decrypt (WITH THE EXTENSION):\t"))

    start = time.time()
    decrypt_file(filename, key, iv)
    dec_time = str(time.time() - start)

    print("\nThe file '"+filename+"' has been DECRYPTED, Successfully!!")
    print("Total Time taken for decryption is:\t"+dec_time+" seconds")
    print("\n\n")


def ex():
    os.system("cls")
    exit()


def err_hand():
    print("Please enter a VALID CHOICE!")


if __name__ == '__main__':
    os.system("cls")
while True:
    print('''
[ 1 ] ENCRYPT a String
[ 2 ] DECRYPT a String
[ 3 ] ENCRYPT a File
[ 4 ] DECRYPT a File
[ 5 ] EXIT\n''')

    try:
        choice = int(input("[<-] Enter your choice:\t"))
        operations = {
            1: enc_str,                 # Encrypt a String
            2: dec_str,                 # Decrypt a String
            3: enc_f,                   # Encrypt a file
            4: dec_f,                   # Decrypt a file
            5: ex                       # exit
        }
        output = operations.get(choice, err_hand)()
        print(output)

    except Exception as e:
        err_hand()
