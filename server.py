import socket
from DES import des_encrypt, des_decrypt, key


def server_program():
    host = socket.gethostname()  # get the hostname
    port = 5000  # initiate port number above 1024

    server_socket = socket.socket()  # get instance
    server_socket.bind((host, port))  # bind host address and port together

    server_socket.listen(1)
    print("Server is listening...")

    conn, address = server_socket.accept()  # accept new connection
    print("Connection from: " + str(address))

    while True:
        data = conn.recv(1024).decode()  # receive encrypted message from client
        if not data:
            break

        # Decrypt received data
        encrypted_binary = ''.join(format(ord(c), '08b') for c in data)
        print("Encrypted message received from Client (binary) :", encrypted_binary)

        decrypted_message = des_decrypt(data, key)
        print("Received from client (decrypted): " + decrypted_message)

        # Get server's reply, encrypt it, and send back to client
        server_reply = input(" -> ")
        encrypted_reply = des_encrypt(server_reply, key)
        conn.send(encrypted_reply.encode())  # send encrypted reply back to client

    conn.close()  # close the connection


if __name__ == '__main__':
    server_program()
