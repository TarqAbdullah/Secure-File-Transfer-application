# Secure-File-Transfer-application
File transfer application that will allow you to transfer any type of files across a LAN. 
This application will encrypt your files that will be sent using AES.

These codes are Python based, and have been tested on Windows 10 OS only.

*The private key is hard coded in both the server and client, you need to change it*

If you want to use the server on a machine that's different than the client's make sure
to write the IP @ in the 'Client.py' and set it to the IP @ of the server and put it inside "".
Ensure you use the same name as the files that are attached with the codes (client_data, server_data).
The server_data should be within the same directory as the 'Server.py' file, and the same 
goes to the 'Client.py' file its folder must be within the same directory.
There are files with different extensions that are available for testing purposes.
If you face issues with the port #, just change it in both the client and the server to any port #.
Provided that the port # is not used.

Make sure to install the imported libraries, in order to assure the proper working of the libraries.
In the Server. Py, there is a command "OS. removes" on line 76 & 145 & on the Client. By line 71 & 159.
This line is commented so that the encryption and decryption process is hidden from the server and client.
In case you want to see the encrypted results just uncomment them.


Steps:
1- Double click on both files (Server & Client).
2- Type 'HELP' in the Client window to get a list of the commands.
3- Issue the command that you want to execute as the following:
	LIST: List all the files from the server.
	PUT <filename.extension>: Upload the file to the server.
	GET <filename.extension>: Download the file from the server.
	DELETE <filename>: Delete a file from the server.
	QUIT: Disconnect from the server.
	HELP: List all the commands.

Note: Commands (list, put, get, delete, quit, help) are not case sensitive,
it can take capital or small letters. However, file name 
are case sensitive you must write the file name as is including its extension.




