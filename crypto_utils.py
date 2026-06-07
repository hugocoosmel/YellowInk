from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

class Clave:
    def __init__(self):
        self.__public_key = None
        self.__private_key = self.obtain_private_key()

    @property
    def public_key(self):
        return self.__public_key

    @property
    def private_key(self):
        return self.__private_key

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
    def __serialize_private(key):
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        return pem

    def obtain_private_key(self):
        return self.__serialize_private(self.__generate_private_key())


if __name__ == '__main__':
    clave = Clave()
    with open('private_key.pem', 'wb') as f:
        f.write(clave.private_key)
