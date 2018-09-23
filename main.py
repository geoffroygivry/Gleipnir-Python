# Copyright (c) 2018 Geoffroy Givry

from controller.blockchain import Blockchain
from controller import magic_key
from pymongo import MongoClient
from atlas.config import glpr_config as glc

server = MongoClient(glc.MONGODB)
db = server.gleipnir


def run(file_in, file_out=None):
    magic_key.generate_magic_keys("proof_mk.bin", "priv_key_proof.pem",
                                  "pub_key_proof.pem")
    special_magic_key = magic_key.get_magic_key("proof_mk.bin",
                                                "priv_key_proof.pem")

    blockchain = Blockchain(special_magic_key,
                            file_path=file_in, chunks=10)
    splitted_data = blockchain._chunk_data()

    for index, bin_data in enumerate(splitted_data):
        data = blockchain.encrypt_block(bin_data)
        previous_block = blockchain.get_previous_block()
        previous_nonce = previous_block['nonce']
        nonce, current_hash = blockchain.nonce_and_hash(previous_nonce)
        previous_hash = blockchain.hash(previous_block)
        blockchain.create_block(data, nonce, current_hash,
                                previous_hash, title=blockchain.file)

    if blockchain.is_chain_valid(blockchain.chain):
        db[blockchain.title].insert_many(blockchain.chain)

    collection = db[blockchain.title]
    blockchain.convert_blocks_to_file(collection, file_name=file_out)
