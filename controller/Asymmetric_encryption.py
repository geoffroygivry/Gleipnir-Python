# Copyright (c) 2018 Geoffroy Givry


# import module Cryptodome
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP


def generate_keys(private_key_file="private.pem", public_key_file="receiver.pem"):
    key = RSA.generate(2048)

    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open(private_key_file, "wb") as file_out:
        file_out.write(private_key)

    with open(public_key_file, "wb") as file_out:
        file_out.write(public_key)
    return private_key, public_key


def encrypt_data(data, file_out, public_key_file="receiver.pem"):
    if isinstance(data, bytes):
        data = data
    else:
        data = data.encode("utf-8")
    with open(file_out, "wb") as file_out:

        recipient_key = RSA.import_key(open(public_key_file).read())
        session_key = get_random_bytes(16)

        # Encrypt the session key with the public RSA key
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        enc_session_key = cipher_rsa.encrypt(session_key)

        # Encrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(data)
        [file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext)]


def decrypt_data(file_in, private_key_file="private.pem"):
    with open(file_in, "rb") as file_in:

        private_key = RSA.import_key(open(private_key_file).read())

        enc_session_key, nonce, tag, ciphertext = \
            [file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1)]

        # Decrypt the session key with the private RSA key
        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)

        # Decrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        return data
