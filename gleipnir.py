# Copyright (c) 2018 Geoffroy Givry
import argparse


import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def get_gleipnir_args():
    """This function provides a set of options that can be called in the
    CLI"""
    parser = argparse.ArgumentParser()
    main_group = parser.add_argument_group("Main options")
    main_group.add_argument("-f", "--file", action="store",
                            help="Set the path of the file to be encrypted.")
    main_group.add_argument("-s", "--split", action="store",
                            help="force the number of blocks that split "
                            "the file.")
    main_group.add_argument("-o", "--output", action="store",
                            help="specify the output path of the blocks.")
    main_group.add_argument("-p", "--privateKey", action="store",
                            help="specify the path of the private key.")
    main_group.add_argument("-n", "--name", action="store",
                            help="creates a custom name for the blocks "
                            "otherwhise it defaults to the factory name.")
    return parser.parse_args()


class GleipnirError(Exception):
    """This is the Gleipnir custom exception handler"""

    def __init__(self, message, errors):

        # Call the base class constructor with the parameters it needs
        super().__init__(message)

        # Now for your custom code...
        self.errors = errors


class Gleipnir(object):
    def __init__(self, file_path, num_of_chunks):
        self.file_path = file_path
        with open(self.file_path, 'rb') as file:
            self.data = file.read()
        self.num_of_chunks = num_of_chunks
        self.key = get_random_bytes(16)

    def __doc__(self):
        return "Class object that allows to split a file into an encrypted " \
            "blockchain. This can be decrypted only with an authenticated key."

    def __repr__(self):
        return "Gleipnir Object"

    def _chunk_data(self):
        """This function is splitting the data in the number
        of chunks entered in the second parameter. It returns a
        generator."""
        for n in range(0, len(self.data) + 1, len(self.data) //
                       self.num_of_chunks):
            yield self.data[0 + n:len(self.data) // self.num_of_chunks + n]

    def encrypt_blocks(self):
        """Method for splitting and encrypting the file into a blockchain."""
        splitted_data = self._chunk_data()
        for index, bin_data in enumerate(splitted_data):
            # Encryption start
            header = b"Sent by Geoffroy Givry."
            data_to_be_encrypted = bin_data

            cipher = AES.new(self.key, AES.MODE_EAX)
            cipher.update(header)

            ciphertext, tag = cipher.encrypt_and_digest(data_to_be_encrypted)
            json_k = ['nonce', 'header', 'ciphertext', 'tag']
            json_v = [b64encode(x).decode("utf-8") for x in [cipher.nonce,
                                                             header,
                                                             ciphertext,
                                                             tag]]
            result = json.dumps(dict(zip(json_k, json_v)))
            with open("block_{:0{numb}d}.json"
                      .format(index,
                              numb=len(str(self.num_of_chunks))),
                      'w') as json_file:
                json_file.write(result)
            # Encryption end

    def decrypt_blocks(self):
        """Method for decrypting the blockchain into the original file."""
        full_bin_data = bytearray()
        for n in range(0, self.num_of_chunks + 1):
            with open('block_{:02d}.json'.format(n)) as f:
                json_input = json.load(f)
            try:
                b64 = json_input
                json_k = ['nonce', 'header', 'ciphertext', 'tag']
                jv = {k: b64decode(b64[k]) for k in json_k}
                cipher = AES.new(self.key, AES.MODE_EAX, nonce=jv['nonce'])
                cipher.update(jv['header'])
                plaintext = cipher.decrypt_and_verify(jv['ciphertext'],
                                                      jv['tag'])
                full_bin_data.extend(plaintext)
            except ValueError:
                print("Incorrect decryption")
        return bytes(full_bin_data)

    def convert_blocks_to_file(self, file_name=None):
        if not file_name:
            file_name = self.file_path
        full_bin_data = self.decrypt_blocks()
        with open(file_name, 'wb') as decrypted_file:
            decrypted_file.write(full_bin_data)
