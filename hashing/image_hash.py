from hashlib import sha256

def compute_sha256(image_path: str) -> str:
    motor = sha256()

    with open(image_path, 'rb') as f:
        bloque = f.read(4096)

        while len(bloque) > 0:
            motor.update(bloque)
            bloque = f.read(4096)

    hash = motor.hexdigest()
    return hash


def compute_phash(image_path: str) -> str:
    pass

if __name__ == '__main__':
    print(compute_sha256('../test/img.png'))