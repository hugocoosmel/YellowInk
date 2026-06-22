import os

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

class CryptoManagerRSA:
    def __init__(self):
        self._private_key_route = '../keys/private_key.pem'
        self._public_key_route = '../keys/public_key.pem'
        self.__private_key = None
        self.__public_key = None

        # Checks if the pair of keys exist

        if os.path.exists(self._private_key_route) and os.path.exists(self._public_key_route):
            print("Loading keys...")
            self.load_keys()
        else:
            print("Generating keys...")
            self.initialize_keys()

    @property
    def public_key(self):
        return self.__serialize_public_key(self.__public_key)

    @property
    def private_key(self):
        return self.__serialize_private_key(self.__private_key)

    # Method that creates the private key
    @staticmethod
    def __generate_private_key():
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        return private_key

    # Method that serializes the private key
    @staticmethod
    def __serialize_private_key(key):
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        return pem

    # Method that generates the public key from the private key
    @staticmethod
    def __generate_public_key(private_key):
        public_key = private_key.public_key()
        return public_key

    # Method that serializes the public key
    @staticmethod
    def __serialize_public_key(key):
        pem = key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem

    # Initializes private and public keys, and stores them
    def initialize_keys(self):
        self.__private_key = self.__generate_private_key()
        self.__public_key = self.__generate_public_key(self.__private_key)

        with open('../keys/private_key.pem', 'wb') as f:
            f.write(self.private_key)

        with open('../keys/public_key.pem', 'wb') as f:
            f.write(self.public_key)

    # Loads private and public keys
    def load_keys(self):
        with open(self._private_key_route, 'rb') as f:
            self.__private_key = serialization.load_pem_private_key(
                f.read(),
                password=None
            )
        with open(self._public_key_route, 'rb') as f:
            self.__public_key = serialization.load_pem_public_key(
                f.read()
            )

    def sign_data(self, data: bytes) -> bytes:
        signature = self.__private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    def verify_data(self, data: bytes, signature: bytes) -> bool:
        try:
            self.__public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False


if __name__ == '__main__':
    gestor = CryptoManagerRSA()
