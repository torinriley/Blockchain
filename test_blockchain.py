from src.blockchain import Blockchain, Transaction, KeyManager

key_manager = KeyManager()
blockchain = Blockchain()
public_key, private_key = key_manager.generate_key_pair()

blockchain.stake(public_key, 100)


for i in range(5):
    tx = Transaction(public_key, f"recipient_address_{i}", 10 + i)
    tx.sign_transaction(private_key)
    blockchain.add_transaction(tx)


for _ in range(5):
    blockchain.mine_block()


for block in blockchain.chain:
    print(f"Index: {block.index}")
    print(f"Previous Hash: {block.previous_hash}")
    print(f"Timestamp: {block.timestamp}")
    print("Transactions:")
    for tx in block.transactions:
        print(f"  Sender: {tx.sender}")
        print(f"  Recipient: {tx.recipient}")
        print(f"  Amount: {tx.amount}")
        print(f"  Signature: {tx.signature}")
        print(f"  Contract ID: {tx.contract_id}")
    print(f"Hash: {block.hash}")
    print(f"Validator: {block.validator}")
    print("--------------")

print("Is blockchain valid?", blockchain.is_chain_valid())
