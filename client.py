import socket
from DES import des_encrypt, des_decrypt, key


def client_program():
    host = socket.gethostname()  # as both code is running on the same pc
    port = 5000  # socket server port number

    client_socket = socket.socket()  # instantiate
    client_socket.connect((host, port))

    while True:
        # Get user input, encrypt, and send it
        message = input(" -> ")
        if message.lower().strip() == 'bye':
            break
        encrypted_message_sent = des_encrypt(message, key)
        client_socket.send(encrypted_message_sent.encode())
        # Receive encrypted reply from server and decrypt it
        data = client_socket.recv(1024).decode()
        # encrypted_message_received = des_encrypt(data, key)
        decrypted_data = des_decrypt(data, key)
        encrypted_binary = ''.join(format(ord(c), '08b') for c in data)
        print("Encrypted message received from server (binary) :", encrypted_binary)
        print("Received from server (decrypted): " + decrypted_data)

    client_socket.close()


if __name__ == '__main__':
    client_program()
