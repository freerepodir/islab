# pip install pycrypto
# pip install cryptography

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from cryptography.fernet import Fernet
import binascii

message = input("Enter the messageto be encrypted.")

key = Fernet.generate_key()
print("\n  Key :",key)

f = Fernet(key)
cipher_text = f.encrypt(message.encode())
print("\n  Cipher Text :",cipher_text)

privateKeyRSA = RSA.generate(1024)
publicKeyRSA  = privateKeyRSA.publickey()
privateKeyRSA_Printable = privateKeyRSA.exportKey().decode('ascii')
publicKeyRSA_Printable  = publicKeyRSA.exportKey().decode('ascii')
print("\n  Private Key (RSA) :",privateKeyRSA_Printable)
print("\n  Public  Key (RSA) :",publicKeyRSA_Printable)

msg = bytes(str(key), 'utf-8')
encryptor = PKCS1_OAEP.new(publicKeyRSA)
encrypted = encryptor.encrypt(msg)
encrypted_key = binascii.hexlify(encrypted)
print("\n  Encrypted Key :",encrypted_key)

digital_envelope = cipher_text + encrypted_key
print("\n  Digital Envelope :",digital_envelope)

decryptor = PKCS1_OAEP.new(privateKeyRSA)
decrypted = decryptor.decrypt(encrypted)
decrypted_key = decrypted.decode('utf-8') 
print("\n  Decrypted Key: ",decrypted_key)

if(str(key) == str(decrypted_key)):
    print("\n  The keys are equal.")
    decrypted_message = f.decrypt(cipher_text).decode()
    print("\n  Decrypted Message: ",decrypted_message)
else:
    print("Error : both keys are not the same.")

