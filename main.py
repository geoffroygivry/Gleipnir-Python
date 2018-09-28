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

    blockchain = Blockchain(special_magic_key, db,
                            file_path=file_in, chunks=4)
    splitted_data = blockchain._chunk_data()
    blockchain.set_db(db)

    for index, bin_data in enumerate(splitted_data):
        data = blockchain.encrypt_block(bin_data)
        previous_block = blockchain.get_previous_block()
        previous_txid = previous_block['transaction_id']
        new_block = blockchain.create_block(data, previous_txid, title=blockchain.file)

        if blockchain.check_prev_block_hash(new_block, previous_block):
            db.BCMain.insert_one(new_block)

    collection = db.BCMain
    blockchain.convert_blocks_to_file(collection, file_name=file_out)
