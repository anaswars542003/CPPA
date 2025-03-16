import ecdsa
import hashlib

# Generate a new ECDSA private key (secp256k1 curve)
private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)

# Get the corresponding public key
public_key = private_key.get_verifying_key()

# Message to sign
message = "Hello, ECDSA!".encode()

# Hash the message (optional but recommended)
message_hash = hashlib.sha256(message).digest()

# Sign the message
signature = private_key.sign(message_hash)

print("Signature:", signature.hex())

# Verify the signature
is_valid = public_key.verify(signature, message_hash)

print("Signature valid:", is_valid)
