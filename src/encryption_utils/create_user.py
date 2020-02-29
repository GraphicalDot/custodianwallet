



from gen_mnemonic import generate_entropy, generate_mnemonic
from key_derivation import generate_bcrypt, generate_scrypt_key
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512, SHA256
from Crypto.Random import get_random_bytes
import hashlib





def create_new_user(email, password):
    encryptionKey = generate_entropy(64*8) ##this will be in bytes and have length 64
    passwordDerivedKey = generate_scrypt_key(password, email)[0] ##this will also be in bytes and have length 16

    ##step3
    encryptedEncryptionKey = aes_encrypt_CBC(passwordDerivedKey, encryptionKey)


    ##step4: passwordhash, The passwordHash serves as the Client’s authentication key against the Server. 
    passwordHash = PBKDF2(passwordDerivedKey, password, 64, count=10, hmac_hash_module=SHA256) ##length will be 64 bytes

    ##step5: (this will be used for the ”forgot password” flow).
    passwordDerivedKeyHash = hashlib.sha512(passwordDerivedKey).hexdigest()
