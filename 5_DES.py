from pyDes import *
plaintext = input("Enter plaintext: ")
key = input("Enter key: ")
mode = ECB
padmode = PAD_PKCS5
k = des(key, mode, padmode=padmode)
ciphertext = k.encrypt(plaintext)
print("Ciphertext:", ciphertext)
decryptedtext = k.decrypt(ciphertext)
print("Decrypted text:", decryptedtext)
