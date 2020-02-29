import os
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode
from loguru import logger
import binascii


def aes_encrypt(key, file_bytes): 
    #return encrypt_CTR_MODE(key, file_bytes) 
    
    ##The nonce and the tag generated will be exactly 16 bytes 
    #ciphertext, tag, nonce = aes_encrypt(xkey, file_bytes) 
    #ciphertext = b"".join([tag, ciphertext, nonce]) 
    #The AES_GCM encrypted file content 
    #secret = binascii.hexlify(ciphertext) 
    if isinstance(file_bytes, str): 
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
    logger.debug(f"Encrypting {plaintext} with {key}")    
    if not isinstance(key, bytes):
        raise Exception("The encryption key must be an instance of bytes")

    
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext, AES.block_size))
    # iv = b64encode(cipher.iv).decode('utf-8')
    # ct = b64encode(ct_bytes).decode('utf-8')
    # result = json.dumps({'iv':iv, 'ciphertext':ct})
    return ct_bytes+cipher.iv



def aes_decrypt_CBC(key, ciphertext):
    # try:
    #     key = binascii.unhexlify(key)
    # except Exception as e:
    #     raise Exception("Key couldnt be unhexlified in aes_decrypt_CBC {e}")

    # try:
    #     ciphertext = binascii.unhexlify(ciphertext)
    # except Exception as e:
    #     raise Exception("Encrypted text couldnt be unhexlified in aes_decrypt_CBC {e}")

    encrypted_text, iv = ciphertext[:-16], ciphertext[-16:]

    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(encrypted_text), AES.block_size)
        print("The message was: ", pt)
    except (ValueError, KeyError):
        print("Incorrect decryption")

    return pt