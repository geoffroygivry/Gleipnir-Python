# Copyright (c) 2018 Geoffroy Givry
import os
from controller import Asymmetric_encryption as ae
from Crypto.Random import get_random_bytes


def generate_magic_keys(magic_key_file, private_key=None, public_key=None):
    magic_key = get_random_bytes(16)
    
    if private_key is not None and public_key is not None:
        ae.generate_keys(private_key, public_key)
        ae.encrypt_data(magic_key, magic_key_file, public_key)

    else:
        ae.generate_keys()
        ae.encrypt_data(magic_key, magic_key_file)


def get_magic_key(magic_key_file, private_key):
    magic_key = ae.decrypt_data(magic_key_file, private_key)
    return magic_key