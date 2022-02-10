# C = Client.
# S = Server.
# U = User.
import os
import socket
import sys
import time

IP = socket.gethostbyname(socket.gethostname()) # @ of the server. inside a "", like this "172.20.10.2"
PORT = 7777
ADDR = (IP, PORT)
FORMAT = "utf-8"  # Encoding & decoding format.
SERVER_DATA_PATH = "server_data"
CLIENT_DATA_PATH = "client_data"
BUFFER_SIZE = 4096

from Crypto.Cipher import AES   
from Crypto.Util.Padding import unpad, pad   
import secrets   
import hashlib   
student_id = "201750750".encode()  # Bytes.   
key = bytes.fromhex(hashlib.sha256(student_id).hexdigest())  # 256-bit or 32 Bytes. Conversion from hex to bytes.   

iv_size = 16  # 128 bits or 16 Bytes.   

#   For the loading bar.
items = list(range(0, 50))
l = len(items)

def main():
    # (Socket family, Type of socket) = (IPv4, TCP). AF_INET means Address Family InterNET for IPV4.
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Connecting the socket to an IP@ and a port #.
    client.connect(ADDR)
    print()
    print("Type 'HELP' to get the list of the commands.")
    print()
    while True:
        # Receiving what the server is sending.
        data = client.recv(BUFFER_SIZE).decode(FORMAT)
        cmd, msg = data.split("@")
        ##########################
        # If the client received from the server GET. [2nd Phase].
        # The [1st Phase], which is below, is intended for sending the data from C to S.
        # This is the [2nd Phase] which is intended for processing the downloaded file.
        if cmd == "GET":
            file_name = msg
            filePath = os.path.join(f"{CLIENT_DATA_PATH}", f"{file_name}")  # Formatting purpose.
            filePath_enc = CLIENT_DATA_PATH + "/" + "ENC" + file_name # Intended for the encrypted file.
            iv = client.recv(BUFFER_SIZE)
            with open(filePath_enc, "wb") as file:
                while True:
                    received = client.recv(BUFFER_SIZE)
                    # If we received 'DONE' from the server
                    # it means that we've received the file fully.
                    if received == "DONE".encode(FORMAT):
                        break
                    file.write(received)
            file.close()
            # Read the received encrypted file.   
            with open(filePath_enc, "rb") as file:   
                data_encrypted = file.read()   
            file.close()   
            # Decrypt the encrypted file.   
            data_bytes = decryption(data_encrypted, iv)   
            os.remove(filePath_enc)  # Remove this file after decrypting the encrypted file.   
            with open(filePath, "wb") as file:   
                file.write(data_bytes)   
            file.close()   
            ####LOADING####
            print()
            loadbar(0, l, prefix='Progress:', suffix='Complete', length=l)
            for i, item in enumerate(items):
                time.sleep(0.0001)
                loadbar(i + 1, l, prefix='Progress:', suffix='Complete', length=l)
            print()
            ####LOADING####
            print("File received from server successfully.")
        ##########################
        if cmd == "DISCONNECTED":  # This a feedback from the server.
            print("System shut down.")
            print()
            loadbar(0, l, prefix='Progress:', suffix='Complete', length=l)
            for i, item in enumerate(items):
                time.sleep(0.0001)
                loadbar(i + 1, l, prefix='Progress:', suffix='Complete', length=l)
            print()
            client.close()
            sys.exit()
        elif cmd == "OK":
            print(f"{msg}")

        data = input("> ")
        data = data.split(" ")  # upper is used to ignore the case of the user's command.
        cmd = data[0].upper()

        if cmd == "HELP":
            client.send(cmd.encode(FORMAT))
        elif cmd == "QUIT":
            # Send 'QUIT' to the server to let it terminate the connection from its side.
            client.send(cmd.encode(FORMAT))
            print("System shut down.")
            ####LOADING####
            print()
            loadbar(0, l, prefix='Progress:', suffix='Complete', length=l)
            for i, item in enumerate(items):
                time.sleep(0.0001)
                loadbar(i + 1, l, prefix='Progress:', suffix='Complete', length=l)
            print()
            ####LOADING####
            client.close()
            sys.exit()
        elif cmd == "LIST":
            client.send(cmd.encode(FORMAT))
        elif cmd == "DELETE":
            # Send to the server the command issued by the U and the file name.
            client.send(f"{cmd}@{data[1]}".encode(FORMAT))
            ####LOADING####
            print()
            loadbar(0, l, prefix='Progress:', suffix='Complete', length=l)
            for i, item in enumerate(items):
                time.sleep(0.01)
                loadbar(i + 1, l, prefix='Progress:', suffix='Complete', length=l)
            print()
            ####LOADING####
        elif cmd == "GET":
            client.send(f"{cmd}@{data[1]}".encode(FORMAT))  # Send the filename and the cmd to server.
        elif cmd == "PUT":
            # Write the proper format of file path.
            path = CLIENT_DATA_PATH + "/" + data[1]
            path_enc = CLIENT_DATA_PATH + "/" + "ENC" + data[1] # Intended for the encrypted file.   
            # Send 'PUT' to the S to let it prepare for this process.
            client.send(f"PUT{data[1]}".encode(FORMAT))
            iv = secrets.token_bytes(iv_size)   
            # Read the plain file.
            with open(path, "rb") as file:
                data_bytes = file.read()
            data_encrypted = encryption(data_bytes, iv)
            # Write the encrypted the file.   
            with open(path_enc, "wb") as file:   
                file.write(data_encrypted)   
            file = open(path_enc, 'rb')  # 'rb' read byte.   
            bytes_read = file.read(BUFFER_SIZE)   
            client.send(iv)   
            while bytes_read:   
                client.send(bytes_read)   
                bytes_read = file.read(BUFFER_SIZE)   
            file.close()   
            # This is to avoid receiving 2 messages as 1
            # this was critical since it was causing an error in file transmission.
            time.sleep(0.3)
            client.send("DONE".encode(FORMAT))  # To tell the server that the sending is finished.
            os.remove(path_enc)  # Remove this file after encryption and sending
            ####LOADING####
            print()
            loadbar(0, l, prefix='Progress:', suffix='Complete', length=l)
            for i, item in enumerate(items):
                time.sleep(0.0001)
                loadbar(i + 1, l, prefix='Progress:', suffix='Complete', length=l)
            print()
            ####LOADING####
        else:
            print("Wrong input, system shut down.")
            ####LOADING####
            print()
            loadbar(0, l, prefix='Progress:', suffix='Complete', length=l)
            for i, item in enumerate(items):
                time.sleep(0.0001)
                loadbar(i + 1, l, prefix='Progress:', suffix='Complete', length=l)
            print()
            ####LOADING####
            client.send("QUIT".encode(FORMAT))  # To tell the S to terminate the connection from its side.
            client.close()
            sys.exit()

def loadbar(iteration, total, prefix='', suffix='', decimals=1, length=100, fill='>'):
    percent = ('{0:.' + str(decimals) + 'f}').format(100 * (iteration / float(total)))
    filledLength = int(length * iteration // total)
    bar = fill * filledLength + '-' * (length - filledLength)
    print(f'\r{prefix} |{bar}| {percent}% {suffix}', end='\r')
    if iteration == total:
        print()

def encryption(data_to_encrypt, iv):   
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad(data_to_encrypt, AES.block_size))  # Padding is done inside.
    return encrypted_data

def decryption(data_to_decrypt, iv):   
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(data_to_decrypt), AES.block_size)
    return plaintext

if __name__ == "__main__":
    main()


