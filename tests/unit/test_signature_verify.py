import json
import logging
import os
from pathlib import Path

import plyvel
import pytest
from pkg_resources import parse_version
from plyvel._plyvel import Error

from loopchain.blockchain import TransactionVerifier
from loopchain.blockchain.blocks import BlockVersioner, BlockVerifier, BlockSerializer
from loopchain.blockchain.transactions import TransactionVersioner

Logger = logging.getLogger(__name__)


@pytest.fixture
def base_dir() -> Path:
    # FIXME : base_dir that you want to test
    base = Path(os.getcwd()).parents[1]
    return base


@pytest.fixture
def plyvel_db(base_dir) -> plyvel.DB:
    base_dir = base_dir / '.storage'
    db_path = Path()
    Logger.info(f"base_dir : {base_dir}")
    if not os.path.exists(base_dir):
        pytest.skip(f"'{base_dir}' does not exist")

    for path in os.listdir(base_dir):
        if path.startswith('db') and path.endswith('icon_dex'):
            db_path = base_dir / path
            break

    Logger.info(f"db_path : {db_path}")
    db = None
    try:
        db = plyvel.DB(db_path.as_posix())
    except (Error, IOError):
        pytest.skip("db data must be prepared for this verify test")
    return db


@pytest.fixture
def block_versioner():
    block_versioner = BlockVersioner()
    # FIXME : block versions

    mainnet_test = False

    if mainnet_test:
        block_versions = {
            "0.1a": 0,
            "0.3": 10324749,
            "0.4": 12640761,
            "0.5": 14473622
        }
    else:
        block_versions = {
            "0.1a": 0,
            "0.4": 1,
            "0.5": 30
        }

    for version, height in block_versions.items():
        block_versioner.add_version(height, version)
    return block_versioner


@pytest.fixture
def tx_versioner():
    hash_versions = {
        "genesis": 0,
        "0x2": 1,
        "0x3": 1
    }
    tx_versioner = TransactionVersioner()
    for tx_version, tx_hash_version in hash_versions.items():
        tx_versioner.hash_generator_versions[tx_version] = tx_hash_version
    return tx_versioner


class TestSignatureVerify:
    def test_verify(self, plyvel_db, block_versioner, tx_versioner):
        """
        1. prepare plyvel db, block_versioner, tx_versioner
        2. pick block, transaction, vote, etc from db
        3. verify block, vote transaction, vote, etc...
        """

        # given db instance, block_versioner, tx_versioner

        block_key = plyvel_db.get(b'last_block_key')

        while True:
            # when get block from db
            block_dumped = plyvel_db.get(block_key)
            Logger.info(f"block_dump : {block_dumped}")
            block_serialized = json.loads(block_dumped)
            block_height = block_versioner.get_height(block_serialized)
            block_version = block_versioner.get_version(block_height)
            block_serializer = BlockSerializer.new(block_version, tx_versioner)
            block = block_serializer.deserialize(block_serialized)
            Logger.info(f"block_height : {block_height}, block_version : {block_version}")

            if block_height == 0:
                break

            # then block verify
            block_verifier = BlockVerifier.new(block_version, tx_versioner)
            block_verifier.verify_signature(block)

            # then vote verify
            if parse_version(block_version) >= parse_version("0.3"):
                Logger.info(f"leader_votes : {block.body.leader_votes}")
                for leader_vote in block.body.leader_votes:
                    if not leader_vote:
                        continue
                    leader_vote.verify()

                Logger.info(f"prev_votes : {block.body.prev_votes}")
                for block_vote in block.body.prev_votes:
                    if not block_vote:
                        continue
                    block_vote.verify()

            # then transaction verify
            for tx in block.body.transactions.values():
                tv = TransactionVerifier.new(tx.version, tx.type(), tx_versioner)
                tv.verify_signature(tx)

            Logger.info(f"prev_hash : {block.header.prev_hash}, {bytes(block.header.prev_hash)}")
            block_key = block.header.prev_hash.hex().encode("utf-8")
