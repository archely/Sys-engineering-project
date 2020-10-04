
#https://cryptography.io/en/latest/fernet/
#https://devqa.io/encrypt-decrypt-data-python/

 -----------------------------

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import cryptography

def keyGenerator(): # private and public key
    privteKey = rsa.generate_private_key(public_exponent=65537, key_size=2048,backend=default_backend())
    publicKey = privateKey.public_key()
    return {"privateKey": privateKey, "publicKey": publicKey} 


def encrypt(publicKey, Encrypt): #encrypts /   public key
    ciphered = publicKey.encrypt(textToEncrypt, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return ciphered

def decrypt(privatKey, ciphered): #decrypts and encrypted  / private key
    noCipheredText = privatKey.decrypt(ciphered, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(), label=None))
    return Ciphered

def symmetric_Encrypt(symmetricKey, Encrypt): #encrypts message / symmetric key
    cipher = Fernet(symmetricKey)
    return cipher.encrypt(Encrypt)

def symmetric_Decrypt(symmetricKey, Decrypt): #decrypts encrypted message / symmetric key
    cipher = Fernet(symmetricKey)
    return cipher.decrypt(Decrypt)


bobkey = {}
bobkey = keyGenerator() 


Alicekey = {}
Alicekey['publicKey'] = bobKey['publicKey'] # bob sends alice his public key
Alicekey['symmetricKey'] = Fernet.generate_key() #alice creates symmetric key


encryptKey = encryption(Alicekey['publicKey'], Alicekey['symmetricKey'])


dcryptKey = decrypt(bobkey["privateKey"], encryptKey)
# encrypted symmetric key is sent to bob
message_dcrypt = symmetric_Decrypt(dcryptKey, symmetric_Encrypt(dcryptKey, message))

message =b"Hello"

print("Message:" + {message_dcrypt.decode()} )
