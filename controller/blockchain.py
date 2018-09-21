# Copyright (c) 2018 Geoffroy Givry

# Importing the libraries
import os
import datetime
import hashlib
import json
from controller import gleipnir

__author__ = "Geoffroy Givry"


class Blockchain(gleipnir.Gleipnir):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.chain = []
        self._set_blockchain_title()
        self.set_data(self.file)
        self._set_blockchain_title()

        if self.file is not None:
            self.create_block("Blockchain created by: {}".format(__author__),
                              nonce=1,
                              current_hash="00000000000000000",
                              previous_hash='0',
                              title=self.file)
        else:
            self.create_block("Blockchain created by: {}".format(__author__),
                              nonce=1,
                              current_hash="00000000000000000",
                              previous_hash='0')

    def create_block(self, data, nonce, current_hash, previous_hash, title=None):
        chain_index = len(self.chain) + 1
        if title is not None:
            block = {'index': chain_index,
                     'block_title': "{}_{:04d}".format(os.path.basename(title),
                                                       chain_index),
                     'timestamp': str(datetime.datetime.utcnow().isoformat()),
                     'data': data,
                     'nonce': nonce,
                     'hash': current_hash,
                     'previous_hash': previous_hash}
        else:
            block = {'index': chain_index,
                     'timestamp': str(datetime.datetime.utcnow().isoformat()),
                     'data': data,
                     'nonce': nonce,
                     'hash': current_hash,
                     'previous_hash': previous_hash}
        self.chain.append(block)
        return block

    def get_previous_block(self):
        return self.chain[-1]

    def nonce_and_hash(self, previous_nonce):
        new_nonce = 1
        current_hash = None
        check_nonce = False
        while check_nonce is False:
            current_hash = hashlib.sha256(str(new_nonce**2 -
                                              previous_nonce**2)
                                          .encode()).hexdigest()
            if current_hash[:4] == '0000':
                check_nonce = True
            else:
                new_nonce += 1
        return new_nonce, current_hash

    def hash(self, block):
        encoded_block = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(encoded_block).hexdigest()

    def is_chain_valid(self, chain):
        previous_block = chain[0]
        block_index = 1
        while block_index < len(chain):
            block = chain[block_index]
            if block['previous_hash'] != self.hash(previous_block):
                return False
            previous_nonce = previous_block['nonce']
            nonce = block['nonce']
            hash_operation = hashlib.sha256(str(nonce**2 - previous_nonce**2)
                                            .encode()).hexdigest()
            if hash_operation[:4] != '0000':
                return False
            previous_block = block
            block_index += 1
        return True
