import time
import logging
import json
import random
from ecdsa import SigningKey, VerifyingKey, SECP256k1
from src.sha256 import SHA256
from cryptography.fernet import Fernet

logging.basicConfig(level=logging.INFO)

class KeyManager:
    def __init__(self):
        self.keys = {}

    def generate_key_pair(self):
        private_key = SigningKey.generate(curve=SECP256k1).to_string().hex()
        public_key = SigningKey.from_string(bytes.fromhex(private_key), curve=SECP256k1).verifying_key.to_string().hex()
        self.keys[public_key] = private_key
        return public_key, private_key

    def get_private_key(self, public_key):
        return self.keys.get(public_key)

class Transaction:
    def __init__(self, sender, recipient, amount, signature=None, contract_id=None):
        self.sender = sender
        self.recipient = recipient
        self.amount = amount
        self.signature = signature
        self.contract_id = contract_id

    def to_dict(self):
        return {
            'sender': self.sender,
            'recipient': self.recipient,
            'amount': self.amount,
            'signature': self.signature,
            'contract_id': self.contract_id
        }

    def sign_transaction(self, private_key):
        sk = SigningKey.from_string(bytes.fromhex(private_key), curve=SECP256k1)
        message = f'{self.sender}{self.recipient}{self.amount}{self.contract_id}'.encode()
        self.signature = sk.sign(message).hex()

    def is_valid(self):
        if self.sender == "0":
            return True
        if not self.signature:
            return False
        vk = VerifyingKey.from_string(bytes.fromhex(self.sender), curve=SECP256k1)
        message = f'{self.sender}{self.recipient}{self.amount}{self.contract_id}'.encode()
        return vk.verify(bytes.fromhex(self.signature), message)

class Block:
    def __init__(self, index, previous_hash, timestamp, transactions, hash, validator):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.transactions = transactions
        self.hash = hash
        self.validator = validator

    @staticmethod
    def calculate_hash(index, previous_hash, timestamp, transactions):
        value = str(index) + str(previous_hash) + str(timestamp) + json.dumps([tx.to_dict() for tx in transactions])
        sha = SHA256()
        return sha.hash(value.encode())

    @staticmethod
    def create_genesis_block():
        return Block(0, "0", int(time.time()), [], "0", "0")

    @staticmethod
    def create_new_block(previous_block, transactions, validator):
        index = previous_block.index + 1
        timestamp = int(time.time())
        hash = Block.calculate_hash(index, previous_block.hash, timestamp, transactions)
        return Block(index, previous_block.hash, timestamp, transactions, hash, validator)

    def to_dict(self):
        return {
            'index': self.index,
            'previous_hash': self.previous_hash,
            'timestamp': self.timestamp,
            'transactions': [tx.to_dict() for tx in self.transactions],
            'hash': self.hash,
            'validator': self.validator
        }

    @staticmethod
    def from_dict(block_dict):
        transactions = [Transaction(**tx) for tx in block_dict['transactions']]
        return Block(
            block_dict['index'],
            block_dict['previous_hash'],
            block_dict['timestamp'],
            transactions,
            block_dict['hash'],
            block_dict['validator']
        )

class Blockchain:
    def __init__(self):
        self.chain = [Block.create_genesis_block()]
        self.transaction_pool = []
        self.stakes = {}
        self.validators = []
        self.spent_transactions = set()

    def get_latest_block(self):
        return self.chain[-1]

    def add_transaction(self, transaction):
        if transaction.is_valid() and transaction not in self.spent_transactions:
            self.transaction_pool.append(transaction)
            self.spent_transactions.add(transaction)
        else:
            logging.error("Invalid or double-spent transaction")

    def stake(self, public_key, amount):
        if public_key in self.stakes:
            self.stakes[public_key] += amount
        else:
            self.stakes[public_key] = amount
        if public_key not in self.validators:
            self.validators.append(public_key)

    def select_validator(self):
        total_stake = sum(self.stakes.values())
        if total_stake == 0:
            return None
        selection = random.uniform(0, total_stake)
        current = 0
        for validator, stake in self.stakes.items():
            current += stake
            if current > selection:
                return validator
        return None

    def mine_block(self):
        validator = self.select_validator()
        if validator is None:
            logging.error("No validators available")
            return
        reward_transaction = Transaction("0", validator, 1)
        self.transaction_pool.append(reward_transaction)
        new_block = Block.create_new_block(self.get_latest_block(), self.transaction_pool, validator)
        if self.is_block_valid(new_block, self.get_latest_block()):
            self.chain.append(new_block)
            self.transaction_pool = []
            logging.info(f"Block added: {new_block.to_dict()}")
        else:
            logging.error("Invalid block, not added to the chain")

    def is_block_valid(self, block, previous_block):
        if block.previous_hash != previous_block.hash:
            return False
        if block.hash != Block.calculate_hash(block.index, block.previous_hash, block.timestamp, block.transactions):
            return False
        return True

    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            if not self.is_block_valid(current_block, previous_block):
                return False
        return True

    def to_dict(self):
        """Convert the blockchain to a dictionary representation."""
        return {
            'chain': [block.to_dict() for block in self.chain],
            'transaction_pool': [tx.to_dict() for tx in self.transaction_pool],
            'stakes': self.stakes
        }

    @staticmethod
    def from_dict(chain_dict):
        """Create a blockchain instance from a dictionary representation."""
        blockchain = Blockchain()
        blockchain.chain = [Block.from_dict(block_dict) for block_dict in chain_dict['chain']]
        blockchain.transaction_pool = [Transaction(**tx) for tx in chain_dict['transaction_pool']]
        blockchain.stakes = chain_dict['stakes']
        return blockchain
