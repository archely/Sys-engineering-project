
#Sources:
#https://cryptography.io/en/latest/fernet/
#https://devqa.io/encrypt-decrypt-data-python/
#https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
#https://devqa.io/encrypt-decrypt-data-python/
 

#generate keys

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet


def keyGenerator(): # private and public key
    privteKey = rsa.generate_private_key(public_exponent=65537, key_size=2048,backend=default_backend())
    publicKey = privateKey.public_key()
    return {"privateKey": privateKey, "publicKey": publicKey} 


def encryption(publicKey, Encrypt): #encrypts /   public key
    ciphered = publicKey.encrypt(textToEncrypt, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return ciphered

def decryption(privatKey, ciphered): #decrypts and encrypted  / private key
    noCipheredText = privatKey.decrypt(ciphered, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(), label=None))
    return Ciphered

def symmetric_Encryption(symmetricKey, Encrypt): #encrypts message / symmetric key
    cipher = Fernet(symmetricKey)
    return cipher.encrypt(Encrypt)

def symmetric_Decryption(symmetricKey, Decrypt): #decrypts encrypted message / symmetric key
    cipher = Fernet(symmetricKey)
    return cipher.decrypt(Decrypt)


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


print("Message:" + {decryptedMsg.decode()} )
