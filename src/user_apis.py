

import aiohttp
import asyncio
import binascii
from loguru import logger
from encryption_utils.key_derivation import generate_bcrypt, generate_scrypt_key, N
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512, SHA256
from encryption_utils.symmetric import  aes_decrypt_CBC, aes_encrypt_CBC
from pywallet import wallet
from pprint import pprint
from create_user import create_new_user
from settings import *

ID_TOKEN = ""

ENCRYPTION_KEY = ""
PASSWORD_DERIVED_KEY = ""
ASYMMETRIC_PRIVATE_KEY = ""





async def signup():
    data = {"username": "testUser", "password": "YOLOjedi98876$%", "email": "saurav@lexim.gold", "name": "First Jedi"}

    async with aiohttp.ClientSession() as session:
        async with session.post(URL_SIGNUP, json=data) as response:
            result = await response.json()
            if not response.status == 200:
                logger.error(result)
                return 
    logger.success(result)
    return 




async def confirm_sign_up(username, email, password, registration_code):
    """
    At this point, you must have received a registration code on your email after a successful signup operation,
    This function will confirm your signup on AWS cognito and update your details in DynamoDB
    necessary for your wallet 
    """
    user = create_new_user(email, password)
    user.update({"username": username, "code": registration_code})
    async with aiohttp.ClientSession() as session:
        async with session.post(URL_CONFIRM_SIGNUP, json=user) as response:
            result = await response.json()
            if not response.status == 200:
                logger.error(result)
                return 
    logger.success(result)
    return 












async def login(username, password):
    async with aiohttp.ClientSession() as session:
        async with session.post(URL_LOGIN, json={'username': username, "password": password}) as response:
            result = await response.json()
            logger.debug(result)
            global ID_TOKEN 
            ID_TOKEN = result["data"]["id_token"]

    return result 




def generate_password_hash(email, password):
    global PASSWORD_DERIVED_KEY
    PASSWORD_DERIVED_KEY = generate_scrypt_key(password, email, 32)[0] ##this will also be in bytes and have length 16
    passwordHash = PBKDF2(PASSWORD_DERIVED_KEY, password, 64, count=10, hmac_hash_module=SHA256) ##length will be 64 bytes
    # logger.debug(passwordDerivedKey)
    # logger.debug(passwordHash)
    return passwordHash.hex()


async def password_hash_login(username, password_hash):
    """
    The Client runs the AES-CBC de-cryption algorithm, with the encryptedEncryptionKey as the ciphertext, the IV and
    the passwordDerivedKey as the secret, returning the plaintext encryptionKey . The
    Client runs the AES-CBC decryption algorithm, with the encryptedAsymmetricPri-
    vateKey as the ciphertext, the IV and the encryptionKey as the secret, returning
    the plaintext asymmetricPrivateKey . The asymmetricPrivateKey is never stored
    in a persistent manner and only exists inside the browser’s process memory,

    """
    async with aiohttp.ClientSession(headers={"Authorization": ID_TOKEN}) as session:
        async with session.post(URL_PASSWORDHASH_LOGIN, json={'username': username, "passwordHash": password_hash}) as response:
            result = await response.json()
            logger.debug(result)
            encryptedEncryptionKey = result["data"]["encryptedEncryptionKey"]
            global ENCRYPTION_KEY, ASYMMETRIC_PRIVATE_KEY
            ENCRYPTION_KEY = aes_decrypt_CBC(PASSWORD_DERIVED_KEY, binascii.unhexlify(encryptedEncryptionKey))
        
            encryptedAsymmetricPrivateKey = result["data"]["encryptedAsymmetricPrivateKey"]
            ASYMMETRIC_PRIVATE_KEY = aes_decrypt_CBC(ENCRYPTION_KEY, binascii.unhexlify(encryptedAsymmetricPrivateKey))


    return result




async def wallet_creation(username):
    """
    To create a new wallet, the user must be signed in, which means the Client has the
    encryptionKey available in the browser’s process memory and a valid JWT.
    """
    mnemonic = wallet.generate_mnemonic()

    logger.debug(mnemonic)
    encryptedMnemonicPhrase = aes_encrypt_CBC(ENCRYPTION_KEY, mnemonic.encode("utf-8"))
    logger.debug(encryptedMnemonicPhrase)

    w = wallet.create_wallet(network="ETH", seed=mnemonic, children=1)
    pprint (w)

    data = {"username": username, 'eth_address': w["address"], "encryptedMnemonicPhrase": encryptedMnemonicPhrase.hex()}

    pprint(data)
    async with aiohttp.ClientSession(headers={"Authorization": ID_TOKEN}) as session:

        async with session.post(URL_ETHEREUM_UPDATE_MNEMONIC_ADDRESS, json=data) as response:
            result = await response.json()
            pprint(result)
    return 



async def get_wallet(username):
    """
    To fetch their wallet from the Server, the user must be signed in, which means the
    Client has theencryptionKey available in the browser’s process memory and a valid
    JWT.
    Step 1: The Client fetches the wallet. The Client calls the relevant Server API.
    If the JWT is valid, the response to the Client will contain the encryptedMnemon-
    icPhrase cipher or the encryptedPrivateKey cipher (the latter in case the wallet was
    created via an imported private key, see 3.5 Wallet Import).
    Step 2: The Client decrypts the wallet. The Client runs the AES-CBC decryp-
    tion algorithm, with the encryptedMnemonicPhrase or the encryptedPrivateKey as
    the ciphertext, the IV, and the encryptionKey as the secret, returning the plaintext
    mnemonicPhrase or privateKey .
    """
    # mnemonic = wallet.generate_mnemonic()

    # logger.debug(mnemonic)
    # encryptedMnemonicPhrase = aes_encrypt_CBC(ENCRYPTION_KEY, mnemonic.encode("utf-8"))
    # logger.debug(encryptedMnemonicPhrase)

    # w = wallet.create_wallet(network="ETH", seed=mnemonic, children=1)
    # pprint (w)

    async with aiohttp.ClientSession(headers={"Authorization": ID_TOKEN}) as session:
        async with session.post(URL_GET_WALLET, json={"username": username}) as response:
            result = await response.json()
    
    decryptedMnemonicPhrase = aes_decrypt_CBC(ENCRYPTION_KEY, binascii.unhexlify(result["data"]["encryptedMnemonicPhrase"]))
    logger.success(f"User Mnemonic Phrase is {decryptedMnemonicPhrase}")

    return 




if __name__ == "__main__":
    data = {"username": "testUser", "password": "YOLOjedi98876$%", "email": "saurav@xyz.com", "name": "First Jedi"}

    
    
    loop = asyncio.get_event_loop()
    loop.run_until_complete(signup())
    loop.run_until_complete(confirm_sign_up(data["username"], data["email"], data["password"], "772081"))
    


    loop.run_until_complete(login(data["username"],data["password"]))
    password_hash = generate_password_hash(data["email"],data["password"])
    logger.debug(password_hash)

    loop.run_until_complete(password_hash_login(data["username"], password_hash))

    logger.debug(f"This is the encryption key {ENCRYPTION_KEY}")
    logger.debug(f"This is the unencrypted RSA private key {ASYMMETRIC_PRIVATE_KEY}")

    #loop.run_until_complete(wallet_creation("graphicaldot"))
    loop.run_until_complete(get_wallet(data["username"]))
    loop.close()
