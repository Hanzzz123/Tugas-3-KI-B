import socket
from DES import des_encrypt, des_decrypt
from rsa import rsa_encrypt, rsa_decrypt
from pka import generate_random_number, verify_signature, pka_public_key, request_client_public_key

# Keys 
server_public_key = (3233, 17)
server_private_key = (3233, 2753)


def server_program():
    host = socket.gethostname()  # get the hostname
    port = 5000  # initiate port number above 1024

    server_socket = socket.socket()  # get instance
    server_socket.bind((host, port))  # bind host address and port together

    server_socket.listen(1)
    print("Server is listening...")

    conn, address = server_socket.accept()  # accept new connection
    print("Connection from: " + str(address))

    # Server asks the Public Key Authority (PKA) for the client's public key.
    print("\n---step 1: server ask for client's public key to PKA---")
    serialized_key, signature = request_client_public_key()
    print("Received client's public key (from PKA): ", serialized_key)
    print("Received Signature (from PKA): ", signature)

    # Verify the signature using the PKA's public key
    print("\n---step 2: verify signature with PKA's public key---")
    if verify_signature(serialized_key, signature, pka_public_key):
        print("Client's public key has been verified successfully.")

        client_key_parts = serialized_key.split(":")
        client_public_key = (int(client_key_parts[0]), int(client_key_parts[1]))
        print("Verified Client Public Key:", client_public_key)

    else:
        print("Failed to verify the client's public key. Terminating connection.")
        conn.close()
        return

    # Initiate handshake protocol
    print("\n---step 3: Initiate handshake protocol---")
    N1 = generate_random_number()
    print("Generate random number N1: ", N1)
    encrypted_N1 = rsa_encrypt(str(N1), client_public_key)
    print("Encrypted N1:", encrypted_N1)

    encrypted_N1 = ','.join(map(str, encrypted_N1))
    conn.send(encrypted_N1.encode())
    print("Status: Sent encrypted N1 to client and waiting for client's response")

    received_encrypted_N1 = list(map(int, conn.recv(1024).decode().split(',')))
    print("Received Encrypted N1 (from client): ", received_encrypted_N1)

    received_encrypted_N2 = list(map(int, conn.recv(1024).decode().split(',')))
    print("Encrypted N2 (from client): ", received_encrypted_N2)

    decrypted_N2 = rsa_decrypt(received_encrypted_N2, server_private_key)
    print("Decrypted N2: ", decrypted_N2)

    encrypted_N2_back = rsa_encrypt(str(decrypted_N2), client_public_key)
    print("Encrypted N2: ", encrypted_N2_back)
    encrypted_N2_back = ','.join(map(str, encrypted_N2_back))
    conn.send(encrypted_N2_back.encode())
    print("Status: Sent the N2 back to client")

    decrypted_N1_back = rsa_decrypt(received_encrypted_N1, server_private_key)
    print("Decrypted N1: ", decrypted_N1_back)
    if decrypted_N1_back == str(N1):
        print("Handshake successful!")
    else:
        print("Handshake failed!")
        conn.close()
        return

    print("\n---step 4: DES Key delivery with Public Key Cryptosystems---")
    des_key = conn.recv(1024).decode()
    des_signature_str = conn.recv(1024).decode()
    des_signature = [int(x) for x in des_signature_str.split(',')]

    received_encrypted_des_key = list(map(int, conn.recv(1024).decode().split(',')))
    print("Received Encrypted Des Key (from client): ", received_encrypted_des_key)

    decrypted_des_key = rsa_decrypt(received_encrypted_des_key, server_private_key)
    print("Received Decrypted Des Key: ", decrypted_des_key)

    # Verify the signature using the client's public key
    if verify_signature(des_key, des_signature, client_public_key):
        print("Des key has been verified successfully.")

    else:
        print("Failed to verify the server's public key. Terminating connection.")
        conn.close()
        return

    print("\n---step 5: Perform DES-based encrypted string transfer as usual---")
    while True:
        data = conn.recv(1024).decode()  # receive encrypted message from client
        if not data:
            break

        # Decrypt received data
        encrypted_binary = ''.join(format(ord(c), '08b') for c in data)
        print("Encrypted message received from Client (binary) :", encrypted_binary)

        decrypted_message = des_decrypt(data, des_key)
        print("Received from client (decrypted): " + decrypted_message)

        # Get server's reply, encrypt it, and send back to client
        server_reply = input(" -> ")
        encrypted_reply = des_encrypt(server_reply, des_key)
        conn.send(encrypted_reply.encode())  # send encrypted reply back to client

    conn.close()  # close the connection


if __name__ == '__main__':
    server_program()
