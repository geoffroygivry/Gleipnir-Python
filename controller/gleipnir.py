# Copyright (c) 2018 Geoffroy Givry
import sys
import os


from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


class GleipnirError(Exception):
    """This is the Gleipnir custom exception handler"""

    def __init__(self, message, errors):

        # Call the base class constructor with the parameters it needs
        super().__init__(message)

        # Now for your custom code...
        self.errors = errors


class Gleipnir:
    def __init__(self):
        self.db = None
        self.file = None
        self.data = None
        self.chunks = None
        self.key = None

    def __doc__(self):
        return "Class object that allows to split a file into an encrypted " \
            "blockchain. This can be decrypted only with an authenticated key."

    def __repr__(self):
        return "Gleipnir Object"

    def _chunk_data(self):
        """This function is splitting the data in the number
        of chunks entered in the second parameter. It returns a
        generator."""
        if self.data is not None and self.chunks is not None:
            for n in range(0, len(self.data) + 1, len(self.data) //
                           self.chunks):
                yield self.data[0 + n:len(self.data) // self.chunks + n]
        return

    def encrypt_block(self, data=None, **kwargs):
        """Method for splitting and encrypting the file into the decentralised
         blockchain."""
        if data is not None:

            base_file = os.path.basename(self.file)
            header = bytes("{} sent by Geoffroy Givry.".format(base_file).encode("utf-8"))

            cipher = AES.new(self.key, AES.MODE_EAX)
            cipher.update(header)

            ciphertext, tag = cipher.encrypt_and_digest(data)
            dict_key = ['nonce', 'header', 'ciphertext', 'tag']
            dict_val = [b64encode(x).decode("utf-8") for x in [cipher.nonce,
                                                               header,
                                                               ciphertext,
                                                               tag]]
            for key, val in kwargs.items():
                dict_key.append(key)
                dict_val.append(b64encode(bytes
                                          (val.encode
                                           ("utf-8"))).decode("utf-8"))
            return dict(zip(dict_key, dict_val))
        else:
            print("Sorry you must enter some data.")
            sys.exit(1)

    def set_db(self, db):
        """Returns the database object inside the Gleipnir class"""
        self.db = db

    def set_file(self, file):
        """Get the path of the file to encrypt."""
        self.file = file

    def set_data(self, file_path):
        """This fucntion converts the file into binary data."""
        if self.file is not None:
            with open(self.file, 'rb') as file:
                self.data = file.read()
        else:
            print("No files has been added. Please choose one file.")
            sys.exit(1)

    def set_chunks(self, num_of_chunks):
        self.chunks = num_of_chunks

    def import_key(self, key_file):
        with open(key_file, "rb") as key:
            self.key = key

    def export_key(self, key_file):
        with open(key_file, "wb") as key:
            key.write(self.key)

    def set_key(self):
        self.key = get_random_bytes(16)
