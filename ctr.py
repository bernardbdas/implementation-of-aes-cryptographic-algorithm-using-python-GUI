# imports
from memory_profiler import profile
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
import binascii
import time
import os
import psutil


def encrypt(src, key):
    print("Current CPU utilization, before encryption is:\t" +
          str(psutil.cpu_percent(interval=1))+"%")
    AES_obj = AES.new(key, AES.MODE_CTR)
    ciphered_data = AES_obj.encrypt(src)
    print("Current CPU utilization, after encryption is:\t" +
          str(psutil.cpu_percent(interval=1))+"%")

    return ciphered_data, AES_obj.nonce


def decrypt(src, key, nonce):
    print("Current CPU utilization, before decryption is:\t" +
          str(psutil.cpu_percent(interval=1))+"%")
    AES_obj = AES.new(key, AES.MODE_CTR, nonce=nonce)
    decrypted_data = AES_obj.decrypt(src)
    print("Current CPU utilization, after decryption is:\t" +
          str(psutil.cpu_percent(interval=1))+"%")

    return decrypted_data


def encrypt_file(filename, key):
    with open(filename, 'rb', buffering=200000) as fo:
        stream = fo.read()
        enc, nonce = encrypt(stream, key)

    with open(filename + ".enc", 'wb', buffering=200000) as fo:
        fo.write(enc)

    os.remove(filename)
    return nonce


def decrypt_file(filename, key, nonce):
    with open(filename, 'rb', buffering=200000) as fo:
        stream = fo.read()
        dec = decrypt(stream, key, nonce)

    with open(filename[:-4], 'wb', buffering=200000) as fo:
        fo.write(dec)

    os.remove(filename)


def enc_str():
    key = str(input("Enter the encryption/decryption Key:\t"))
    key = bytes(key, 'utf-8')
    key = pad(key, AES.block_size)
    src = input("Enter data to encrypt:\t")
    src = bytes(src, 'utf-8')
    start = time.time()
    ciphered_data, nonce = encrypt(src, key)
    enc_time = str(time.time() - start)
    ciphered_data = str(binascii.hexlify(ciphered_data))
    nonce = str(binascii.hexlify(nonce))

    print('''
    CIPHERED DATA:\t'''+str(ciphered_data[2:-1])+'''              
    NONCE VALUE:\t'''+str(nonce[2:-1])
          )
    print('''
    *****************************************************************************
    *                                                                           *
    *   OPEN A NEW WINDOW IN YOUR NOTEPAD                                       *
    *   SELECT THE CIPHERED DATA WITH YOUR MOUSE AND RIGHT CLICK TO COPY IT     *
    *   PASTE THE CIPHERED DATA IN YOUR NOTEPAD                                 *
    *   SELECT THE NONCE VALUE WITH YOUR MOUSE AND RIGHT CLICK TO COPY IT       *
    *   PASTE THE NONCE VALUE IN YOUR NOTEPAD                                   *
    *                                                                           *
    *   ABOVE ALL, NEVER FORGET YOUR encryption/decryption KEY!                 *
    *                                                                           *
    *****************************************************************************
    ''')
    print("\tTotal Time taken for encryption is:\t"+enc_time+" seconds")
    print("\n\n")


def dec_str():
    key = str(input("Enter the encryption/decryption Key:\t"))
    key = bytes(key, 'utf-8')
    key = pad(key, AES.block_size)
    src = input("Enter DATA to decrypt:\t")
    nonce = input("Enter NONCE value:\t")
    src = binascii.unhexlify(src)
    nonce = binascii.unhexlify(nonce)
    start = time.time()
    deciphered_data = decrypt(src, key, nonce)
    dec_time = str(time.time() - start)
    deciphered_data = deciphered_data.decode('ascii')

    print("\nDECIPHERED DATA:\t"+deciphered_data)
    print("Total Time taken for encryption is:\t"+dec_time+" seconds")
    print("\n\n")


def enc_f():
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
    nonce = encrypt_file(filename, key)
    enc_time = str(time.time() - start)

    nonce = str(binascii.hexlify(nonce))

    print("\n\tThe file '"+filename+"' has been ENCRYPTED, Successfully!!")
    print("\n\n\tNONCE VALUE:\t"+nonce[2:-1])
    print('''
    *****************************************************************************
    *                                                                           *
    *   OPEN A NEW WINDOW IN YOUR NOTEPAD                                       *
    *   SELECT THE NONCE VALUE WITH YOUR MOUSE AND RIGHT CLICK TO COPY IT       *
    *   PASTE THE NONCE VALUE IN YOUR NOTEPAD                                   *
    *                                                                           *
    *   ABOVE ALL, NEVER FORGET YOUR encryption/decryption KEY!                 *
    *                                                                           *
    *****************************************************************************
    
    ''')
    print("\tTotal Time taken for encryption is:\t"+enc_time+" seconds")
    print("\n\n")


def dec_f():
    key = str(input("Enter the encryption/decryption Key:\t"))
    key = bytes(key, 'utf-8')
    key = pad(key, AES.block_size)
    print("\nThese are the files in your current directory:-")
    print("********************************************************************************\n")
    os.system("dir /b")
    print("\n********************************************************************************\n")
    filename = str(
        input("Enter the NAME of the file you want to decrypt (WITH THE EXTENSION):\t"))
    nonce = input("Enter NONCE value:\t")

    nonce = binascii.unhexlify(nonce)

    start = time.time()
    decrypt_file(filename, key, nonce)
    dec_time = str(time.time() - start)

    print("\nThe file '"+filename+"' has been DECRYPTED, Successfully!!")
    print("Total Time taken for decryption is:\t"+dec_time+" seconds")
    print("\n\n")


def ex():
    os.system("cls")
    exit()


def err_hand():
    print("Please enter a VALID CHOICE!")


# driver-code
if __name__ == '__main__':
    os.system("cls")

    print('''
        ==========================================================================================================================
        ||                                                                                                                      ||
        ||      This code is used to encrypt and decrypt strings as well as files                                               ||
        ||      We use the Rijndael-128 algorithm, also known as the AES algorithm to do our encryptions and decryptions        ||
        ||      Here we are using the algorithm in Counter (CTR mode), where we make use of nonce                               ||
        ||      Use of nonce makes our program more secure as the randomness of the algorithm increases                         ||
        ||      In CTR mode, the program makes use of multi-core CPU, so the working is also faster and efficient               ||
        ||      Absence of initialization vector makes CTR mode work faster                                                     ||
        ||                                                                                                                      ||
        ==========================================================================================================================
        ''')

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
