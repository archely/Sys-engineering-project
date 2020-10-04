'''
Sources:
 https://cryptography.io/en/latest/fernet/
 https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
 https://devqa.io/encrypt-decrypt-data-python/
 https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
'''

#generates
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet


def keyGenerator(): # private and public key
    privteKey = rsa.generate_private_key(public_exponent=65537, key_size=2048,backend=default_backend())
    publicKey = privateKey.public_key()
    return {"privateKey": privateKey, "publicKey": publicKey} 


def encryption(pubKey, textToEncrypt): #encrypts /   public key
    cipheredText = pubKey.encrypt(textToEncrypt, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return cipheredText

def decryption(privatKey, cipheredText): #decrypts and encrypted  / private key
    noCipheredText = privatKey.decrypt(cipheredText, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(), label=None))
    return noCipheredText

def sym_Encryption(symmetricKey, msgToEncrypt): #encrypts message / symmetric key
    cipher = Fernet(symmetricKey)
    return cipher.encrypt(msgToEncrypt)

def sym_Decryption(symmetricKey, msgToDecrypt): #decrypts encrypted message / symmetric key
    cipher = Fernet(symmetricKey)
    return cipher.decrypt(msgToDecrypt)


bobkey = {}
bobkey = keyGenerator() 

# bob sends alice his public key
Alicekey = {}
Alicekey['publicKey_Bob'] = bobKey['publicKey'] 
Alicekey['symmetricKey_Alice'] = Fernet.generate_key() #alice creates symmetric key


encryptionProcess = encryption(Alicekey['publicKey_Bob'], Alicekey['symmetricKey_Alice'])


decryptionProcess = decryption(bobkey["privateKey"], encryptionProcess)
# encrypted symmetric key is sent to bob
decryptedMsg = symmetric_Decryption(decryptionProcess, symmetric_Encryption(decryptionProcess, secretMsg))

print(f' Message: {decryptedMsg.decode()}')