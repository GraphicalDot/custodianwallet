import os
from Crypto.Protocol.KDF import scrypt
from loguru import logger
N = 2**16 ##meant for ram
R = 10
P = 10
import binascii
import bcrypt

from loguru import logger



def generate_bcrypt(password):
    if isinstance(password, str):
        password = password.encode()
    hashed =bcrypt.hashpw(password, bcrypt.gensalt())
    return hashed


def check_bcrypt(password: str, hashed_password: str):
    if isinstance(password, str):
        password = password.encode()

    if isinstance(hashed_password, str):
        hashed_password = hashed_password.encode()

    logger.warning(password)
    logger.warning(hashed_password)
    if bcrypt.checkpw(password, hashed_password):
        return True
    return False




def generate_scrypt_key(password, salt, key_length):
    ##return bytes of keys, returns list in case of keys > 1
    ##returns hex encoded salt and key byte array
    logger.debug(f"Generating scrypt key with {password} and salt {salt}, with keylength {N}, R {R} and p {P}")

    keys = scrypt(password,  salt, key_length, N, R, P, 1)
    return keys, salt