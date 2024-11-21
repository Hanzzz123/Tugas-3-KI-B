import socket
from DES import des_encrypt, des_decrypt, key as Des_Key
from rsa import rsa_encrypt, rsa_decrypt
from pka import generate_random_number, request_server_public_key, pka_public_key, verify_signature, sign_key

# Keys for Client
client_public_key = (2537, 13)  # (n, e)
client_private_key = (2537, 937)  # (n, d)

def client_program():
    host = socket.gethostname()  # as both code is running on the same pc
    port = 5000  # socket server port number

    client_socket = socket.socket()  # instantiate
    client_socket.connect((host, port))

    #  Step 1: Request the server's public key from the PKA
    print("\n---step 1: Client ask for server's public key to PKA---")
    serialized_key, signature = request_server_public_key()
    print("Received server's public key (from PKA): ", serialized_key)
    print("Received Signature (from PKA): ", signature)

    # Step 2: Verify the signature using the PKA's public key
    print("\n---step 2: Verify signature with PKA's public key---")
    if verify_signature(serialized_key, signature, pka_public_key):
        print("Server's public key has been verified successfully.")
        print("Received server's public key: ", serialized_key)
        print("Received Signature: ", signature)

        server_key_parts = serialized_key.split(":")
        server_public_key = (int(server_key_parts[0]), int(server_key_parts[1]))
        print("Verified Server Public Key:", server_public_key)
        
    else:
        print("Failed to verify the server's public key. Terminating connection.")
        client_socket.close()
        return

    print("\n---step 3: Handle handshake protocol---")
    encrypted_N1 = list(map(int, client_socket.recv(1024).decode().split(',')))
    print("Receiving encrypted N1 (From server): ", encrypted_N1)

    decrypted_N1 = rsa_decrypt(encrypted_N1, client_private_key)
    print("Client decrypted N1:", decrypted_N1)

    N2 = generate_random_number()
    print("Generate random number N2: ", N2)

    encrypted_N1_back = rsa_encrypt(decrypted_N1, server_public_key)
    print("Encrypted N1 again: ", encrypted_N1_back)
    encrypted_N1_back = ','.join(map(str, encrypted_N1_back))

    encrypted_N2 = rsa_encrypt(str(N2), server_public_key)
    print("Encrypted N2: ", encrypted_N2)
    encrypted_N2 = ','.join(map(str, encrypted_N2))

    client_socket.send(encrypted_N1_back.encode())
    client_socket.send(encrypted_N2.encode())
    print("Status: N1 and N2 has been sent to the Server")

    received_data = list(map(int, client_socket.recv(1024).decode().split(',')))
    print("Receiving Encrypted N2 (From server): ", received_data)
    decrypted_N2_back = rsa_decrypt(received_data, client_private_key)
    print("Decrypted N2 (from server): ", decrypted_N2_back)

    if decrypted_N2_back == str(N2):
        print("Handshake successful!")
    else:
        print("Handshake failed!")
        client_socket.close()
        return

    print("\n---step 4: DES Key delivery with Public Key Cryptosystems---")
    print("Get Des Key: ", Des_Key)
    des_key, des_signature = sign_key(Des_Key, client_private_key)
    des_key_str = str(des_key)
    des_signature_str = ','.join(map(str, des_signature))
        
    client_socket.send(des_key_str.encode())
    client_socket.send(des_signature_str.encode())

    encrypted_des_key = rsa_encrypt(Des_Key, server_public_key)
    print("Encrypted Des Key: ", encrypted_des_key)
        
    encrypted_des_key = ','.join(map(str, encrypted_des_key))
    client_socket.send(encrypted_des_key.encode())
    
    print("\n---step 5: Perform DES-based encrypted string transfer as usual---")
    while True:
        # Get user input, encrypt, and send it
        message = input(" -> ")
        if message.lower().strip() == 'bye':
            break
        encrypted_message_sent = des_encrypt(message, Des_Key)
        client_socket.send(encrypted_message_sent.encode())
        # Receive encrypted reply from server and decrypt it
        data = client_socket.recv(1024).decode()
        # encrypted_message_received = des_encrypt(data, key)
        decrypted_data = des_decrypt(data, Des_Key)
        encrypted_binary = ''.join(format(ord(c), '08b') for c in data)
        print("Encrypted message received from server (binary) :", encrypted_binary)
        print("Received from server (decrypted): " + decrypted_data)

    client_socket.close()


if __name__ == '__main__':
    client_program()
