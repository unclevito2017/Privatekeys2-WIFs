import base58
import hashlib
from binascii import unhexlify, Error as BinasciiError

def private_key_to_wif(private_key, compressed=True):
    try:
        extended_key = '80' + private_key

        if compressed:
            extended_key += '01'

        hashed_key = unhexlify(extended_key)
        checksum = hashlib.sha256(hashlib.sha256(hashed_key).digest()).digest()[:4]

        wif_key = extended_key + checksum.hex()

        wif_key_base58 = base58.b58encode(unhexlify(wif_key)).decode('utf-8')

        return wif_key_base58
    except BinasciiError:
        # Handle odd-length string error (or any other binascii error)
        print(f"Ignoring invalid private key: {private_key}")
        return None

def bulk_private_keys_to_wif(private_keys, compressed=True):
    wif_keys = []
    for private_key in private_keys:
        wif_key = private_key_to_wif(private_key, compressed)
        if wif_key is not None:
            wif_keys.append(wif_key)
    return wif_keys

file_path = 'pk.txt'

with open(file_path, 'r') as file:
    private_keys = [line.strip() for line in file]

compressed_wif_keys = bulk_private_keys_to_wif(private_keys, compressed=True)
uncompressed_wif_keys = bulk_private_keys_to_wif(private_keys, compressed=False)

# Write WIFs to file
output_file_path = 'wif.txt'
with open(output_file_path, 'w') as output_file:
    for compressed_wif, uncompressed_wif in zip(compressed_wif_keys, uncompressed_wif_keys):
        output_file.write(f"{compressed_wif}\n{uncompressed_wif}\n")
