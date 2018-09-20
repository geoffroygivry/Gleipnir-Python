# Copyright (c) 2018 Geoffroy Givry
import os
from controller import Asymmetric_encryption as ae
from Crypto.Random import get_random_bytes


def generate_magic_key(file):
    ae.generate_keys()
    magic_key = get_random_bytes(16)
    ae.encrypt_data(magic_key, file)
    decrypted_magic_key = ae.decrypt_data(file)
    if decrypted_magic_key == magic_key:
        print "yes!"