



from encryption_utils.gen_mnemonic import generate_entropy
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
    """
    Step 1: The User generates a secret. User inputs an email and a password into
    the client.
    
    Step 2: The Client generates an encryption key.
    The client gener-ates an encryptionKey of 64 random bytes using the browser’s native function
    Crypto.getRandomValues().

    Step 3: The Client encrypts the encryption key. The Client selects a Key
    Derivation Function (KDF). The default choice is PBKDF2. PBKDF2 is a password-
    based key derivation function that uses a password, a variable-length salt, and an
    iteration count and applies a pseudorandom function to these to produce a key. Our
    implementation uses SHA-256 as the pseudorandom function.
    The Client selects the number off KDF iterations to run. The default choice is
    100,000. The client runs the KDF with the password as the secret, the email as the
    salt and the relevant number of iterations. The KDF function returns a key, which
    we will call passwordDerivedKey.
    The Client runs the AES-CBC encryption algorithm, with the encryptionKey as
    the plaintext, the passwordDerivedKey as the secret, and 16 random bytes as the
    IV (using the browser’s native function Crypto.getRandomValues()), returning the
    encryptedEncryptionKey cipher, composed of the encryptedEncryptionKey, the IV
    and the encryption algorithm mode.
    
    Step 4: The Client hashes the password. The Client runs PBKDF2 with SHA-
    256 as the pseudorandom function, using the passwordDerivedKey as the secret and
    the password as the salt, running a single iteration. This returns the passwordHash.
    The passwordHash serves as the Client’s authentication key against the Server.
    
    Step 5: The Client generates a forgot password hash. The client hashes the
    passwordDerivedKey using SHA-512, returning a passwordDerivedKeyHash (this will
    be used for the ”forgot password” flow).
    
    Step 6: The Client generates and encrypts an asymmetric key pair for
    secure client-to-client communication. The Client runs RSA-OAEP 2048 with
    a SHA-1 hashing algorithm to generate a pair of both an asymmetricPublicKey
    5and asymmetricPrivateKey. The Client runs the AES-CBC encryption algorithm,
    with the asymmetricPrivateKey as the plaintext and the encryptionKey as the se-
    cret, returning the encryptedAsymmetricPrivateKey cipher, composed of the en-
    cryptedAsymmetricPrivateKey, the IV and the encryption algorithm mode. For now,
    these asymmetricPublicKey and encryptedAsymmetricPrivateKey have no function
    but will be used later on as asymmetric keys for secure client-to-client communica-
    tion.

    """



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





