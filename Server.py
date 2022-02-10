# C = Client.
# S = Server.
# U = User.
import os
import socket
import time
import threading
import math

from Crypto.Cipher import AES   
from Crypto.Util.Padding import unpad, pad   
import secrets   
import hashlib   

IP = socket.gethostbyname(socket.gethostname())
PORT = 7777
ADDR = (IP, PORT)
BUFFER_SIZE = 4096
FORMAT = "utf-8"
SERVER_DATA_PATH = "server_data"
CLIENT_DATA_PATH = "client_data"

student_id = "201750750".encode()  # Bytes.   
key = bytes.fromhex(hashlib.sha256(student_id).hexdigest())  # 256-bit or 32 Bytes. Conversion from hex to bytes.   
temp = hashlib.sha256(student_id)   

iv_size = 16  # 128 bits or 16 Bytes.   

#   For the loading bar.
items = list(range(0, 50))
l = len(items)

def convert_size(size_bytes):
    if size_bytes == 0:
        return "0B"
    size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return "%s %s" % (s, size_name[i])

def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected.")
    conn.send("OK@Welcome to the File Server.".encode(FORMAT))

    while True:
        # Receive data or messages from the C.
        received = conn.recv(BUFFER_SIZE).decode(FORMAT)
        # The '@' is used to separate the message.
        data = received.split("@")
        cmd = data[0]
        if received[0:3] == "PUT":
            file_name = received[3:]
            filePath = os.path.join(f"{SERVER_DATA_PATH}", f"{file_name}")  # Formatting purpose.
            filePath_enc = SERVER_DATA_PATH + "/" + "ENC" + file_name  # Intended for the encrypted file.   
            iv = conn.recv(BUFFER_SIZE)   
            # Write the received encrypted file.   
            with open(filePath_enc, "wb") as f:  # 'wb' write byte.   
                while True:   
                    received = conn.recv(BUFFER_SIZE)   
                    # When the S receives 'DONE' it means the whole file   
                    # data has been sent.   
                    if received == "DONE".encode(FORMAT):   
                        break   
                    f.write(received)   
            # Read the encrypted data.   
            with open(filePath_enc, "rb") as file:   
                encrypted_bytes = file.read()   
            data_decrypted = decryption(encrypted_bytes, iv)   
            os.remove(filePath_enc) # To remove the encrypted file to replace it with the decrypted.   
            with open(filePath, "wb") as file:   
                file.write(data_decrypted)   
            print("File received from client successfully.")   
            # Send this to the client. OK means everything worked well   
            send_data = "OK@File uploaded successfully."   
            conn.send(send_data.encode(FORMAT))   

        if cmd == "LIST":
            # Get the files in the server file.
            files = os.listdir(SERVER_DATA_PATH)
            send_data = "OK@"

            if len(files) == 0:
                send_data += "The server directory is empty"
            else:  # Print all the files that exist on the server's file.
                send_data += "\n"
                for f in files:
                    path_mix = SERVER_DATA_PATH + "/" + f
                    file_size = convert_size(os.path.getsize(path_mix))
                    send_data += f + "\t" + "\t" + "\t" + file_size + "\n"
            conn.send(send_data.encode(FORMAT))

        elif cmd == "DELETE":
            files = os.listdir(SERVER_DATA_PATH)
            send_data = "OK@"
            filename = data[1]

            if len(files) == 0:
                send_data += "The server directory is empty"
            else:
                if filename in files:
                    filePath = os.path.join(f"{SERVER_DATA_PATH}", f"{filename}")  # Formatting purpose.
                    os.remove(filePath)
                    send_data += "File deleted successfully."
                else:
                    send_data += "File not found."

            conn.send(send_data.encode(FORMAT))

        elif cmd == "QUIT":
            break
        elif cmd == "GET":
            # Write the format of the file path.
            # This is dependent on the OS, in this case it's tested on Windows10.
            path = SERVER_DATA_PATH + "/" + data[1]
            path_enc = SERVER_DATA_PATH + "/" + "ENC" + data[1]  # Intended for the encrypted file.   
            # Send the file name back to the C.   
            conn.send(f"GET@{data[1]}".encode(FORMAT))   
            iv = secrets.token_bytes(iv_size)   
            # Read the plain file.   
            with open(path, "rb") as file:   
                data_bytes = file.read()   
            data_encrypted = encryption(data_bytes, iv)   
            # Write the encrypted the file.   
            with open(path_enc, "wb") as file:   
                file.write(data_encrypted)   
            conn.send(iv)   
            file = open(path_enc, 'rb')  # 'rb' read byte.   
            bytes_read = file.read(BUFFER_SIZE)   
            while bytes_read:   
                conn.send(bytes_read)   
                bytes_read = file.read(BUFFER_SIZE)   
            file.close()   
            # This is to avoid receiving 2 messages as 1
            # this was critical since it was causing an error in file transmission.
            time.sleep(0.3)
            conn.send(b"DONE")  # To tell the server that the sending is finished.
            print("The file has been sent to the client successfully.")
            os.remove(path_enc)  # Remove this file after encryption and sending
        elif cmd == "HELP":
            data = "OK@"
            data += "LIST: List all the files from the server.\n"
            data += "PUT <filename.extension>: Upload the file to the server.\n"
            data += "GET <filename.extension>: Download the file from the server.\n"
            data += "DELETE <filename>: Delete a file from the server.\n"
            data += "QUIT: Disconnect from the server.\n"
            data += "HELP: List all the commands."

            conn.send(data.encode(FORMAT))

    print(f"[DISCONNECTED] {addr} disconnected")
    conn.close()

def main():
    print("[STARTING] Server is starting")
    ####LOADING####
    print()
    loadbar(0, l, prefix='Progress:', suffix='Complete', length=l)
    for i, item in enumerate(items):
        time.sleep(0.01)
        loadbar(i + 1, l, prefix='Progress:', suffix='Complete', length=l)
    print()
    ####LOADING####
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(ADDR)
    # Within the parentheses we can specify how many parallel connections are allowed.
    # In this case I wrote nothing, this means it'll allow any client to connect.
    server.listen()
    print(f"[LISTENING] Server is listening on {IP}:{PORT}.")

    while True:
        # Accept any client that connects to our PORT#.
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        print(f"[ACTIVE CONNECTIONS] {threading.activeCount() - 1}")

def loadbar(iteration, total, prefix='', suffix='', decimals=1, length=100, fill='>'):
    percent = ('{0:.' + str(decimals) + 'f}').format(100 * (iteration / float(total)))
    filledLength = int(length * iteration // total)
    bar = fill * filledLength + '-' * (length - filledLength)
    print(f'\r{prefix} |{bar}| {percent}% {suffix}', end='\r')
    if iteration == total:
        print()

def encryption(data_to_encrypt, iv):   
    print(f'IV = {iv.hex()}')
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad(data_to_encrypt, AES.block_size))  # Padding is done inside.
    return encrypted_data

def decryption(data_to_decrypt, iv):   
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(data_to_decrypt), AES.block_size)
    return plaintext

if __name__ == "__main__":
    main()


