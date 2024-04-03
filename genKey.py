from Crypto.Random import get_random_bytes


def generate_key():
    return get_random_bytes(16)

key = generate_key()

print('Your key is: ' ,key.hex() )