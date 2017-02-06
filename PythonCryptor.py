'''
Written By SaEeD.
Description:  AES En/Decryptor, En/Decrypt files with AES algorithm.


Encryption:  Original File size + Random IV + SHA256 hashed password (32 bytes. regardless of how big the password is)
             + Saving Magic Message
             + Padding the file if needed.

Decryption: Original file size + Saved IV + Encrypted Magic Message + Remove padding data(if any)

*** Some changes to Cypto libarary: https://stackoverflow.com/questions/24804829/another-one-about-pycrypto-and-paramiko
**** Main reference website: http://eli.thegreenplace.net/2010/06/25/aes-encryption-of-files-in-python-with-pycrypto
***** Useful for testing:  http://aes.online-domain-tools.com/
'''
import io , sys, os, getpass
import time
import hashlib
import Crypto
import struct
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

#Magic Message to check if the file/passphrase is valid 
#Encrypted Hash would be saved on encrypted file
magic_msg = b'!!MASTER SAEED!!'

#Encryption Method
def EncryptFile(FileName, chunksize=64*1024):
    print("[+]Encrypting file: " , FileName)
    filesize = os.path.getsize(FileName)
    print("[+]File size: ", filesize, " Bytes")

    Passphrase = getpass.getpass(prompt = "[-]Please enter Password / Passphrase: ")
    key = hashlib.sha256(Passphrase.encode()).digest()
    iv = get_random_bytes(16)
    mode = AES.MODE_CBC
    print("[+]Password is: ", Passphrase)
    print("[+]Password SHA256 hash: ", key.hex())
    print("[+]16 Bytes Random IV: \t", iv.hex())
    encryptor = AES.new(key, mode, iv)
    
    #Encrypt and save Magic Message
    magic_msg_enc =  encryptor.encrypt(magic_msg)

    print("[+]Magic Message: " , magic_msg_enc.hex()) 
    print("\n[*]Encrypting........")
    print("[+]Start time: %s" % time.strftime('%H:%M:%S'))
    
    out_file = FileName + '.enc'
    with open(FileName, 'rb') as inFile:
        with open(out_file, 'wb') as outFile:
            #Quadword Little-Endian order 
            # more info can be found here: https://docs.python.org/3/library/struct.html
            outFile.write(struct.pack('<Q', filesize) )
            outFile.write(iv)
            outFile.write(magic_msg_enc)
            while True:
                #Read chunk of file
                chunk = inFile.read(chunksize)
                print("\r[+]Elapsed time: %s" % time.strftime('%H:%M:%S') , end='\r')
                
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    print("[!]Added padding to file.      ")
                    chunk += (' ' * (16 - len(chunk) % 16)).encode()
                
                outFile.write(encryptor.encrypt(chunk))
                
    print("\n[+]Done! :)")

#Decryption method
def DecryptFile(FileName, chunksize=24*1024):
    print("[+]Decrypting file: " , FileName)
    #Create file with .dec extention to avoid overwrite 
    out_file = os.path.splitext(FileName)[0] + ".dec"
    
    with open(FileName, 'rb') as inFile:
        #Read the Original file size to remove padding data later: https://docs.python.org/3/library/struct.html#format-characters

        origsize = struct.unpack('<Q', inFile.read(struct.calcsize('Q')))[0]
        iv = inFile.read(16)
        print("[+]File Original Size: " , origsize, " Bytes")
        Passphrase = getpass.getpass(prompt = "[-]Please enter Password / Passphrase: ")
        key = hashlib.sha256(Passphrase.encode()).digest()
        mode = AES.MODE_CBC
        print("[+]Password is: ", Passphrase)
        print("[+]Password SHA256 hash: ", key.hex())
        print("[+]IV from File: " , iv.hex())
        decryptor = AES.new(key, mode, iv)
        
        magic_msg_hash = inFile.read(16)        
        print("[+]Reading Magic Hash: " , magic_msg_hash.hex())
        
        magic_msg_dec =  decryptor.decrypt(magic_msg_hash)
        #try:
        #    print("Content: " , magic_msg_dec.decode())
        #except UnicodeDecodeError:
        #    pass
        if magic_msg_dec == magic_msg:
            print("[+]Valid File, Magic Messages Match.")
        else:
            print("[!]Invalid Magic Message, Wrong Passphrase or File.")
            exit(-1)
        with open(out_file, 'wb') as outFile:
            print("\n[*]Decrypting...")
            print("[+]Start time: %s" % time.strftime('%H:%M:%S'))
            
            while True:
                chunk = inFile.read(chunksize)
                print("\r[+]Elapsed time: %s" % time.strftime('%H:%M:%S') , end='\r')
                if len(chunk) == 0:
                    break
                outFile.write(decryptor.decrypt(chunk))
            
            print("\n[+]Removing Padding Data.")
            outFile.truncate(origsize)
        
    print("[+]Done! :)")


def usage():
    print ("***Usage:" , sys.argv[0], "<-e | -d> for En/Decryption <Path to File>")


if __name__ == "__main__":
    print("+"*36)
    print("[--== Welcome To SaEeD Cryptor ==--]")
    print("+"*36 , "\n")

    if(len(sys.argv) !=3):
        usage()
        exit(-1)
    Filename = sys.argv[2]

    if(os.path.isfile(Filename) != True):
        print("[!]Target file NOT found")
        usage()
        exit(-1)
    if sys.argv[1] == '-e':
        EncryptFile(Filename)
    elif sys.argv[1] == '-d':
        DecryptFile(Filename)
    else:
        print("[!]Invalid Operation")
        usage()
        exit(-1)

