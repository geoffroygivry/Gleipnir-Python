# Copyright (c) 2018 Geoffroy Givry

# Importing the libraries
import os
import datetime
import hashlib
import json
from controller import gleipnir
import pymongo
from controller import gleipnir_utils as gu

__author__ = "Geoffroy Givry"


class Blockchain(gleipnir.Gleipnir):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.chain = [x for x in self.db.BCMain.find().sort('_id', pymongo.DESCENDING)]
        self.previous_block = self.get_previous_block()
        self._set_blockchain_title()
        self.set_data(self.file)
        self._set_blockchain_title()

    def create_block(self, data, previous_txid, chunk_index, title=None):
        prev_block = self.get_previous_block()
        chain_index = prev_block['input']['index'] + 1
        if title is not None:
            block = {'input': {
                'index': chain_index,
                'block_title': "{}_{:04d}".format(os.path.basename(title),
                                                  chunk_index + 1),
                'timestamp': str(datetime.datetime.utcnow().isoformat()),
                'data': data,
                'previous_txid': previous_txid
            },
                'metadata': []
            }

        else:
            block = {'input': {
                'index': chain_index,
                'block_title': "Gleipnir Untitled Block",
                'timestamp': str(datetime.datetime.utcnow().isoformat()),
                'data': data,
                'previous_txid': previous_txid
            },
                'metadata': []
            }

        nonce = 1
        check_nonce = False
        while check_nonce is False:
            block['input']['nonce'] = nonce
            block_hash = hashlib.sha256(str(self.format_dict_to_block(block)).encode()).hexdigest()
            if block_hash[:3] == '000':
                block["transaction_id"] = block_hash
                check_nonce = True
            else:
                nonce += 1

        return block

    def get_previous_block(self):
        return [x for x in self.db.BCMain.find().sort('_id', pymongo.DESCENDING).limit(1)][0]

    def hash(self, block):
        formated_block = gu.JSONEncoder().encode(block)
        encoded_block = json.dumps(formated_block, sort_keys=True).encode()
        return hashlib.sha256(encoded_block).hexdigest()

    def format_dict_to_block(self, block):
        return json.dumps(block, sort_keys=True)

    def check_prev_block_hash(self, block, previous_block):
        comp_block = {"input": previous_block["input"], "metadata": previous_block["metadata"]}
        check_hash = hashlib.sha256(str(self.format_dict_to_block(comp_block)).encode()).hexdigest() == block["input"]["previous_txid"]
        return check_hash

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
