



from encryption_utils.gen_mnemonic import generate_entropy, generate_mnemonic
from encryption_utils.key_derivation import generate_bcrypt, generate_scrypt_key, N
from encryption_utils.symmetric import aes_encrypt_CBC, aes_decrypt_CBC
from encryption_utils.asymmetric import generate_rsa_keypair
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512, SHA256
from Crypto.Random import get_random_bytes
import hashlib
import pprint
from loguru import logger

from Crypto.Random import get_random_bytes


def create_new_user(email, password):
    ##key to be either 16, 24 or 32 bytes long (for AES-128, AES-196 and AES-256, respectively)
    encryptionKey = get_random_bytes(32) ##this will be in bytes and have length 32 bytes
    passwordDerivedKey = generate_scrypt_key(password, email, 32)[0] ##this will also be in bytes and have length 16

    ##step3
    encryptedEncryptionKey = aes_encrypt_CBC(passwordDerivedKey, encryptionKey)

    ##checking for correct AES encryption
    text = aes_decrypt_CBC(passwordDerivedKey, encryptedEncryptionKey)
    
    if text != encryptionKey:
        logger.error("Encryption and decryption of encryption_key couldnt be done")

    logger.success("Encryption and decryption of encryption_key done successfully")



    ##step4: passwordhash, The passwordHash serves as the Client’s authentication key against the Server. 
    passwordHash = PBKDF2(passwordDerivedKey, password, 64, count=10, hmac_hash_module=SHA256) ##length will be 64 bytes

    ##step5: (this will be used for the ”forgot password” flow).
    passwordDerivedKeyHash = hashlib.sha512(passwordDerivedKey).hexdigest()


    ##step6:
    asymmetricPublicKey, asymmetricPrivateKey = generate_rsa_keypair()

    encryptedAsymmetricPrivateKey = aes_encrypt_CBC(encryptionKey, asymmetricPrivateKey)

    return {"KDF": "scrypt", "iterations": N, "email": email, 
            "passwordHash": passwordHash.hex(), 
            "passwordDerivedKeyHash": passwordDerivedKeyHash, 
            "encryptedEncryptionKey": encryptedEncryptionKey.hex(),  
            "asymmetricPublicKey": asymmetricPublicKey.hex(),
            "encryptedAsymmetricPrivateKey": encryptedAsymmetricPrivateKey.hex()}






if __name__ == "__main__":
    email = "houzier.saurav@gmail.com"
    password = "Groot1234#"
    pprint.pprint(create_new_user(email, password))