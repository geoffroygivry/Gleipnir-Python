# Copyright (c) 2018 Geoffroy Givry
import sys
import os


from base64 import b64encode, b64decode
from Crypto.Cipher import AES


class GleipnirError(Exception):
    """This is the Gleipnir custom exception handler"""

    def __init__(self, message, errors):

        # Call the base class constructor with the parameters it needs
        super().__init__(message)

        # Now for your custom code...
        self.errors = errors


class Gleipnir:
    def __init__(self, magic_key, db=None, file_path=None, chunks=None):
        self.db = db
        self.file = file_path
        self.title = None
        self.data = self.set_data(self.file)
        self.chunks = chunks
        self.key = magic_key
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

    def decrypt_blocks(self, db_collection):
        """Method for decrypting the blockchain into the original file."""
        full_bin_data = bytearray()
        for n in sorted(list(db_collection.find()),
                        key=lambda x: x['input']['block_title'].split('_')[-1]): #TODO : change the hard coded keys of the blockchain dict model andnf put it in a centralised module.
            if isinstance(n['input']['data'], dict): # TODO : same has previous.
                json_input = n['input']['data'] # TODO: same as previous
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

    def convert_blocks_to_file(self, db_collection, file_name=None):
        if not file_name:
            file_name = self.file
        full_bin_data = self.decrypt_blocks(db_collection)
        with open(file_name, 'wb') as decrypted_file:
            decrypted_file.write(full_bin_data)
        print("the file {} has been decrypted!".format(file_name))

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

    def _set_blockchain_title(self):
        if self.file is not None:
            filename, ext = os.path.splitext(os.path.basename(self.file))
            self.title = filename

    def get_blockchain_title(self):
        return self.title
