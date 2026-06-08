from crypto_utils import CryptoManager

if __name__ == '__main__':
    print("Generando claves...")
    gestor = CryptoManager()

    with open('./keys/public_key.pem', 'wb') as f:
        f.write(gestor.public_key)
    with open('./keys/private_key.pem', 'wb') as f:
        f.write(gestor.private_key)

    print("Claves generadas con éxito.")
    print()
    print("Firmando el mensaje 'HOLA MUNDO'")
    firma = gestor.sign_data(b'HOLA MUNDO')
    print('Firma: ', firma)
    print()
    print("Validando firma")
    print(gestor.verify_data(b'HOLA MUNDO', firma))
