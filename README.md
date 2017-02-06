# Python-Cryptor

Written By SaEeD.
Description:  AES En/Decryptor, En/Decrypt files with AES algorithm.


Encryption:  Original File size + Random IV + SHA256 hashed password (32 bytes. regardless of how big the password is)
             + Saving Magic Message
             + Padding the file if needed.

Decryption: Original file size + Saved IV + Encrypted Magic Message + Remove padding data(if any)

*** Some changes to Cypto libarary: https://stackoverflow.com/questions/24804829/another-one-about-pycrypto-and-paramiko
**** Main reference website: http://eli.thegreenplace.net/2010/06/25/aes-encryption-of-files-in-python-with-pycrypto
***** Useful for testing:  http://aes.online-domain-tools.com/

