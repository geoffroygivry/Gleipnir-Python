# Copyright (c) 2018 Geoffroy Givry
import sys
import os


from base64 import b64encode, b64decode
import hashlib
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
    def __init__(self, file_path=None, chunks=None):
        self.db = None
        self.file = file_path
        self.title = None
        self.data = self.set_data(self.file)
        self.chunks = chunks
        self.key = self.set_key()
        # self.key = hashlib.sha256(key.encode()).digest()
        self._set_blockchain_title()

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
        """This function converts the file into binary data."""
        if self.file is not None:
            with open(self.file, 'rb') as file:
                self.data = file.read()
        else:
            self.data = None

    def set_chunks(self, num_of_chunks):
        """Function that's returns the number of chunks of the file"""
        self.chunks = num_of_chunks

    def import_key(self, key_file):
        with open(key_file, "rb") as key:
            self.key = key

    def export_key(self, key_file):
        with open(key_file, "wb") as key:
            key.write(self.key)

    def set_key(self):
        self.key = get_random_bytes(16)

    def _set_blockchain_title(self):
        if self.file is not None:
            filename, ext = os.path.splitext(os.path.basename(self.file))
            self.title = filename

    def get_blockchain_title(self):
        return self.title
