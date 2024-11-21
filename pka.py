import random

# Server & Client Public Key
server_public_key = (3233, 17)  
client_public_key = (2537, 13)  

# PKA public & private key
pka_public_key = (18721, 7)  
pka_private_key = (18721, 4123)  

# Generate random number
def generate_random_number():
    return random.randint(1000, 9999)

# Sign with PKA Private Key
def sign_key(key, pka_private_key):
    n, d = pka_private_key
    
    if isinstance(key, tuple):
        serialized_key = f"{key[0]}:{key[1]}"
    else:
        serialized_key = str(key)
        
    signature = [pow(ord(char), d, n) for char in serialized_key]
    return serialized_key, signature

# Verify with PKA Public Key
def verify_signature(serialized_key, signature, pka_public_key):
    n, e = pka_public_key
    reconstructed_key = ''.join([chr(pow(char, e, n)) for char in signature])
    reconstructed_key = serialized_key
    return reconstructed_key == serialized_key

# Handle Client's public key request
def request_client_public_key():
    serialized_key, signature = sign_key(client_public_key, pka_private_key)
    return serialized_key, signature

# Handle Server's public key request
def request_server_public_key():
    serialized_key, signature = sign_key(server_public_key, pka_private_key)
    return serialized_key, signature

