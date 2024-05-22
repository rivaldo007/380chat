# Secure Chat

## Synopsis
Secure Chat is a simple, yet effective, encrypted chat application developed using C and OpenSSL. This project demonstrates basic client-server communication with SSL/TLS encryption, ensuring that all messages exchanged between the client and server are secure.

## Important Notes
- Ensure you have OpenSSL installed on your system.
- The project includes a self-signed certificate (`cert.pem`) and a private key (`key.pem`). For production use, it's recommended to obtain a certificate from a trusted Certificate Authority (CA).

## Details

### Client (client.c)
The client program connects to a specified server using SSL/TLS. It establishes a secure connection and allows the user to send and receive encrypted messages.

**Key Functions:**
- `OpenConnection`: Establishes a connection to the server using the provided hostname and port.
- `InitCTX`: Initializes the SSL context.
- `ShowCerts`: Displays the server's certificates.
- `ClientChat`: Manages the chat session, sending user input to the server and displaying server responses.

### Server (server.c)
The server program listens on a specified port for incoming client connections. It uses SSL/TLS to secure the communication, allowing encrypted message exchanges.

**Key Functions:**
- `OpenListener`: Opens a listening socket on the specified port.
- `InitServerCTX`: Initializes the SSL context for the server.
- `LoadCertificates`: Loads the server's certificate and private key.
- `Servlet`: Handles the communication with the client, reading messages and sending responses.

## Compiling the Skeleton
To compile the client and server programs, ensure you have gcc and OpenSSL development libraries installed. Use the following commands:

```bash
gcc -o client client.c -lssl -lcrypto
gcc -o server server.c -lssl -lcrypto

```bash
./server 12345

```bash
./client localhost 12345
