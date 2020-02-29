import os
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from base64 import b64encode

def generate_aes_key(number_of_bytes): 
     #return get_random_bytes(number_of_bytes) 
     return os.urandom(number_of_bytes) 


def aes_encrypt(key, file_bytes): 
    #return encrypt_CTR_MODE(key, file_bytes) 
    
    ##The nonce and the tag generated will be exactly 16 bytes 
    #ciphertext, tag, nonce = aes_encrypt(xkey, file_bytes) 
    #ciphertext = b"".join([tag, ciphertext, nonce]) 
    #The AES_GCM encrypted file content 
    #secret = binascii.hexlify(ciphertext) 
    if isinstance(file_bytes, str): s
        file_bytes = file_bytes.encode() 
    cipher = AES.new(key, AES.MODE_GCM) 
    ciphertext, tag = cipher.encrypt_and_digest(file_bytes) 
    nonce = cipher.nonce 
    return b"".join([tag, ciphertext, nonce]) 


def aes_decrypt(key, ciphertext):

    if isinstance(ciphertext, str):
        ciphertext = ciphertext.encode()
    tag, nonce = ciphertext[:16], ciphertext[-16:]
    cipher = AES.new(key, AES.MODE_GCM, nonce)
    decrypted_text = cipher.decrypt_and_verify(ciphertext[16:-16], tag)
    return decrypted_text


def aes_encrypt_CBC(key, plaintext):
    if not isinstance(key, bytes):
        raise Exception("The encryption key must be an instance of bytes")
    if len(key) != 16:
        raise Exception("The length of encryption key must be 16")
    cipher = AES.new(passwordDerivedKey, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext, AES.block_size))
    # iv = b64encode(cipher.iv).decode('utf-8')
    # ct = b64encode(ct_bytes).decode('utf-8')
    # result = json.dumps({'iv':iv, 'ciphertext':ct})
    return ct_bytes+cipher.iv