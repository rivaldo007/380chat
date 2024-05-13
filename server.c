//server.c
//Alexandr Voronovich
//Rivaldo Lumelino
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUFFER 1024
#define FAIL -1

// Opens a listening socket on the specified port
int OpenListener(int port) {
    int sd;
    struct sockaddr_in addr;

    sd = socket(PF_INET, SOCK_STREAM, 0); // Create socket
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    // Bind the socket
    if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        perror("Can't bind port");
        abort();
    }
    // Listen on the socket
    if (listen(sd, 10) != 0) {
        perror("Can't configure listening port");
        abort();
    }
    return sd;
}

// Initializes SSL context for use with the server
SSL_CTX* InitServerCTX(void) {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms();  // Initialize OpenSSL crypto algorithms
    SSL_load_error_strings();      // Load SSL error strings
    method = TLS_server_method();  // Create new server-method instance
    ctx = SSL_CTX_new(method);     // Create new context from method
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

// Load the certificate and key files
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile) {
    // Load certificate into the SSL context
    if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    // Load private key into the SSL context
    if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    // Verify private key
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}

// Handles connection for each client
void Servlet(SSL* ssl, int client_fd) {
    char buf[BUFFER];
    char reply[BUFFER + 256];
    int sd, bytes;
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);

    if (SSL_accept(ssl) == FAIL) {
        ERR_print_errors_fp(stderr);
    } else {
        // Get client's IP and port number
        getpeername(client_fd, (struct sockaddr *)&addr, &len);
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr.sin_addr, client_ip, INET_ADDRSTRLEN);
        int client_port = ntohs(addr.sin_port);

        while (1) {
            bytes = SSL_read(ssl, buf, sizeof(buf)); // Read data from the client
            if (bytes > 0) {
                buf[bytes] = 0;
                printf("Message from [%s:%d]: %s\n", client_ip, client_port, buf);
                snprintf(reply, sizeof(reply), "Reply from server to [%s:%d]: %s", client_ip, client_port, buf);
                SSL_write(ssl, reply, strlen(reply)); // Send response to the client
            } else {
                ERR_print_errors_fp(stderr);
                break;
            }
        }
    }
    sd = SSL_get_fd(ssl); // Get the socket descriptor
    SSL_free(ssl);        // Free SSL state
    close(sd);            // Close the connection
}

int main(int argc, char *argv[]) {
    SSL_CTX *ctx;
    int server;
    char *portnum;

    // Check command line arguments
    if (argc != 2) {
        printf("Usage: %s <portnum>\n", argv[0]);
        exit(0);
    }

    SSL_library_init();  // Initialize OpenSSL library
    portnum = argv[1];
    ctx = InitServerCTX();  // Initialize SSL context
    LoadCertificates(ctx, "cert.pem", "key.pem"); // Load certificates
    server = OpenListener(atoi(portnum)); // Open a listening socket

    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    SSL *ssl;

    // Accept connections indefinitely
    while (1) {
        int client = accept(server, (struct sockaddr*)&addr, &len); // Accept a client connection
        printf("Connection: %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        ssl = SSL_new(ctx);  // Create a new SSL state with context
        SSL_set_fd(ssl, client);  // Set the connection socket to SSL state
        Servlet(ssl, client); // Process client connection
    }

    close(server); // Close server socket
    SSL_CTX_free(ctx); // Free SSL context
    return 0;
}







