

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

def generate_rsa_keypair():

    key = RSA.generate(2048)
    private_key = key.export_key()
    
    public_key = key.publickey().export_key()
    return (public_key, private_key)


def pem_encoding(key, filepath, filename):
    if not filename.endswith(".pem"):
        raise Exception("Only pem encoding is allowed")
    file_out = open(filepath, "wb")
    file_out.write(key)
    return 

def read_pem_encoding(filepath):
    return RSA.import_key(open(filepath).read())





def rsa_encrypt(public_key, plaintext):

    # Encrypt the session key with the public RSA key
    if not isinstance(plaintext, bytes):
        plaintext = plaintext.encode("utf-8")

    if not isinstance(public_key, bytes):
        raise Exception("Public key should be in bytes")

    public_key = RSA.import_key(public_key) 
    cipher_rsa = PKCS1_OAEP.new(public_key)
    enc_plaintext = cipher_rsa.encrypt(plaintext)
    return enc_plaintext
    # # Encrypt the data with the AES session key
    # cipher_aes = AES.new(session_key, AES.MODE_EAX)
    # ciphertext, tag = cipher_aes.encrypt_and_digest(data)


def rsa_decrypt(private_key, enc_plaintext):
    
    # Encrypt the session key with the public RSA key
    if not isinstance(enc_plaintext, bytes):
        enc_plaintext = enc_plaintext.encode("utf-8")

    private_key = RSA.import_key(private_key) 
    cipher_rsa = PKCS1_OAEP.new(private_key)
    plaintext = cipher_rsa.decrypt(enc_plaintext)
    return plaintext