import json
from crypto.rsa import CryptoManagerRSA

DELIMITER = b"||YI-SPLIT||"

def build_payload(author: str, date: str, image_hash: str, algo_hash:str,
                  algo_crypto:str, crypto_manager: CryptoManagerRSA):

    payload = {
        "author": author,
        "date": date,
        "image_hash": image_hash,
        "algo_hash": algo_hash,
        "algo_crypto": algo_crypto
    }

    payload_str = json.dumps(payload)
    payload_bytes = payload_str.encode('utf-8')
    firma = crypto_manager.sign_data(payload_bytes)

    return payload_bytes + DELIMITER + firma

def unpack_payload(payload_total_bytes):
    payload_encoded, signature = payload_total_bytes.split(DELIMITER,1) # List [PAYLOAD, SIGNATURE]
    payload_decoded = json.loads(payload_encoded.decode('utf-8'))

    return payload_decoded, signature

if __name__ == "__main__":
    manager = CryptoManagerRSA()
    payload_total = build_payload('Alice', '12-12-2012', 'test', 'SHA-256', 'RSA', manager)
    print(payload_total)
    print(unpack_payload(payload_total))
