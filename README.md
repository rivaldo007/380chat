Secure Chat Application

Overview

This project is a secure chat application developed as part of a computer security course project at CCNY. The application facilitates secure communication between users over a network using encryption and decryption to ensure the privacy and integrity of the messages exchanged.

Features

Secure client-server communication
Diffie-Hellman key exchange for secure key generation
AES-256-CBC encryption for message confidentiality
HMAC-SHA256 for message integrity
Multi-threaded to handle concurrent sending and receiving of messages
GTK-based GUI for a user-friendly chat interface


Installation

Prerequisites
GCC compiler
GMP library
OpenSSL library
GTK+ 3.0
Building the Project
Clone the repository:


**Building the Project**
-`git clone <repository_url>`
-`cd <repository_directory>`


Compile the code:
-`gcc -o chat chat.c dh.c key.c keys.c util.c -lgmp -lssl -lcrypto -lgtk-3`

Usage
Running the Server
To start the server, run the following command:

-`./chat --listen --port <port_number>`

This will make the server listen for incoming connections on the specified port.

Running the Client
To start the client and connect to the server, run:

-`./chat --connect <server_hostname> --port <port_number>`


Command Line Options

-c, --connect HOST: Attempt a connection to the specified host.
-l, --listen: Listen for new connections.
-p, --port PORT: Listen or connect on the specified port (defaults to 1337).
-h, --help: Show the usage message and exit.


Security Overview

Key Exchange and Generation
The application uses the Diffie-Hellman (DH) key exchange protocol to securely generate a shared secret key between the client and server. The DH parameters (prime numbers and generator) are initialized from a file.


Encryption and Decryption

Messages are encrypted using AES-256-CBC to ensure confidentiality. The encryption key is derived from the DH key exchange process. Each message is encrypted before being sent over the network and decrypted upon receipt.


Message Integrity

HMAC-SHA256 is used to verify the integrity of messages. A hash-based message authentication code (HMAC) is calculated for each message using a secret key derived from the shared DH key.


Secure Key Storage and Handling

The application securely initializes and shreds DH keys to prevent unauthorized access. Keys are stored using GMP's mpz_t data type, and sensitive data is cleared from memory after use.


Network Security

The application uses secure network programming practices, such as:

Retrying on temporary errors (EINTR and EWOULDBLOCK)
Proper error handling and resource cleanup
Secure socket communication


Contributing

Contributions are welcome! Please fork the repository and submit pull requests for any enhancements or bug fixes.

