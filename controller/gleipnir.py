# Copyright (c) 2018 Geoffroy Givry
import sys
import argparse


import json
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
      if self.data is not None and self.chunks is not None:
        for n in range(0, len(self.data) + 1, len(self.data) //
                       self.chunks):
            yield self.data[0 + n:len(self.data) // self.chunks + n]
      return

  def encrypt_blocks(self):
    """Method for splitting and encrypting the file into the decentralised blockchain."""
    if self.db is not None and self.data is not None and self.chunks is not None:
        db = self.db

        splitted_data = self._chunk_data()
        for index, bin_data in enumerate(splitted_data):
            # Encryption start
            header = b"{} sent by Geoffroy Givry.".format(os.path.basename(self.file))
            data_to_be_encrypted = bin_data

            cipher = AES.new(self.key, AES.MODE_EAX)
            cipher.update(header)

            ciphertext, tag = cipher.encrypt_and_digest(data_to_be_encrypted)
            json_k = ['nonce', 'header', 'ciphertext', 'tag']
            json_v = [b64encode(x).decode("utf-8") for x in [cipher.nonce,
                                                             header,
                                                             ciphertext,
                                                             tag]]
            result = dict(zip(json_k, json_v))
    else:
        print("Sorry you must enter some parameters.")
        sys.exit(1)

  def get_db(self, db):
    """Returns the database object inside the Gleipnir class"""
    self.db = db
    
  def get_file(self, file):
    """Get the path of the file to encrypt."""
    self.file = file
    
  def get_data(self, file_path):
    """This fucntion converts the file into binary data."""
    if self.file is not None:
      with open(self.file, 'rb') as file:
          self.data = file.read()
    else:
      print("No files has been added. Please choose one file.")
      sys.exit(1)
        
  def get_chunks(self, num_of_chunks):
    self.chunks = num_of_chunks