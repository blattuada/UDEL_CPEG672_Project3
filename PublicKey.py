import math, random, rsa, binascii, hashlib
from Cryptodome.Util.number import *
from Cryptodome.Cipher import AES
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import PublicFormat, pkcs12, PrivateFormat

# Create a shared key for encryption using EC SECP256R1 keys. 
def ECDHE_SharedKey(privateKey, publicKey):
    sharedKey = privateKey.exchange(ec.ECDH(), publicKey)
    return(binascii.hexlify(sharedKey))

# Sign message using RSA keys
def RSA_Signing(message, privateKey):
    hashValue = rsa.compute_hash(message, 'SHA-1')
    signature = rsa.sign_hash(hashValue, privateKey, 'SHA-1')
    return(signature)

# Verify signed message using RSA public keys 
def RSA_Verification(message, publicKey, signature):
    print('RSA digital signature verified')
    return(rsa.verify(message, signature, publicKey))

# Encrypt the secret message using the shared EC key and 
def AES_GCM_Encrypt(nonceValue, message, sharedKey):
    cipher_GCM=AES.new(sharedKey, AES.MODE_GCM, nonce=nonceValue)
    return([nonceValue,cipher_GCM.encrypt(message)])

# Decrypt the ciphertext using the provided nonce and known shared key.
def AES_GCM_Decrypt(nonceValue, message, sharedKey):
    cipher_GCM=AES.new(sharedKey, AES.MODE_GCM, nonce=nonceValue)
    return(cipher_GCM.decrypt(message))

# Super secret message, nonceValue and message array that is going to be sent to Bob
plainText = b'A super secret packet that is only meant for bob to see'
print('Alice has a plaintext message she wants to share with bob, the message is:\n' + str(plainText))
nonceValue = b'6E6F6E6365'
messageArray = [nonceValue, plainText]

# Define the RSA key for signature/verification. This will allow recipients to confirm they are 
# Talking to who they think they are talking to.  
(AlicePubRSAkey, AlicePrivRSAkey) = rsa.newkeys(512)
(BobPubRSAkey, BobPrivRSAkey) = rsa.newkeys(512)

# EC keys for Alice
alicePrivate = ec.generate_private_key(ec.SECP256R1())
alicePublic = alicePrivate.public_key()

# EC keys for Bob
bobPrivate = ec.generate_private_key(ec.SECP256R1())
bobPublic = bobPrivate.public_key() 

# Bob and Alice sign their EC public keys 
print('Alice and Bob share their EC Diffie Hellman public keys so they can create a shared secret. They both digitally sign their public keys with their RSA private keys')
signedAlicePublicKeyMessage = RSA_Signing((alicePublic.public_bytes(encoding=serialization.Encoding.OpenSSH, format=serialization.PublicFormat.OpenSSH)), AlicePrivRSAkey)
signedBobPublicKeyMessage = RSA_Signing((bobPublic.public_bytes(encoding=serialization.Encoding.OpenSSH, format=serialization.PublicFormat.OpenSSH)), BobPrivRSAkey)

# They both verify they have the correct public key using RSA signatures. 
print('Bob performs a verification using Alices public RSA key:')
RSA_Verification((alicePublic.public_bytes(encoding=serialization.Encoding.OpenSSH, format=serialization.PublicFormat.OpenSSH)), AlicePubRSAkey, signedAlicePublicKeyMessage)
print('Alice performs a verification using Bobs public RSA key:')
RSA_Verification((bobPublic.public_bytes(encoding=serialization.Encoding.OpenSSH, format=serialization.PublicFormat.OpenSSH)), BobPubRSAkey, signedBobPublicKeyMessage)

# Alice generates the shared key 
print('Alice and bob both now know they have each others legitimate public key. Alice makes a shared secret using Bobs public key and her prviate key. The shared secret they will both use to encrypt and decrypt the message is:')
print(ECDHE_SharedKey(alicePrivate, bobPublic))

print('Alice and Bob know that the nonce value will be sent in front of the message which can be used for AES GCM encryption and decryption')

print('Alice encrypts her plaintext using a random nonce value and the shared key. Alice signs the encrypted message with her Private RSA key prior to sending to Bob. Bob sucessfully verifies the ecnrypted message originated from Alice.')
# Encrypt useing the shared key and the nonce value sent to Bob
encryptedMessage = AES_GCM_Encrypt(messageArray[0], messageArray[1], binascii.unhexlify(ECDHE_SharedKey(alicePrivate, bobPublic)))
signedAliceSecretMessage = RSA_Signing(encryptedMessage[1], AlicePrivRSAkey)
RSA_Verification(encryptedMessage[1], AlicePubRSAkey, signedAliceSecretMessage)
print('Bob receives the following encrypted message and nonce Value: ')
print(encryptedMessage)

# Bob decrypts using the shared key, the encrypted message and the provided nonce value. 
print('Bob decrypts using the shared key and nonce value and get the following plaintext message, which matches what Alices plaintext value.')
decryptedMessage = AES_GCM_Decrypt(encryptedMessage[0], encryptedMessage[1], binascii.unhexlify(ECDHE_SharedKey(bobPrivate, alicePublic)))
print(decryptedMessage)
