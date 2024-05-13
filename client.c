//client.c
//Alexandr Voronovich
//Rivaldo Lumelino
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define FAIL    -1
#define BUFFER  1024

// Establishes a connection to a server using hostname and port
int OpenConnection(const char *hostname, int port) {
    int sd;
    struct hostent *host;
    struct sockaddr_in addr;

    if ((host = gethostbyname(hostname)) == NULL) {
        perror("Unable to get host");
        abort();
    }
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);

    if (connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        close(sd);
        perror("Cannot connect to host");
        abort();
    }
    return sd;
}

SSL_CTX* InitCTX(void) {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms();  // Load the cryptographic algorithms
    SSL_load_error_strings();      // Load SSL error strings
    method = TLS_client_method();  // Use a client-side SSL/TLS method
    ctx = SSL_CTX_new(method);     // Create a new SSL context for the method
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

// Display the server's certificates
void ShowCerts(SSL* ssl) {
    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl); // Get the certificate from the SSL context
    if (cert != NULL) {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    } else {
        printf("No certificates.\n");
    }
}

void ClientChat(SSL* ssl, const char* server_hostname, int port) {
    char buf[BUFFER];
    char input[BUFFER + 32];

    printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
    ShowCerts(ssl);

    while (1) {
        printf("\nMESSAGE TO SERVER (%s:%d): ", server_hostname, port);//Doesn't work
        fgets(input + 20, BUFFER - 20, stdin); // Read input from user
        snprintf(input, sizeof(input), "From client to [%s:%d]: %s", server_hostname, port, input + 20);
        SSL_write(ssl, input, strlen(input)); // Send formatted message to server

        int bytes = SSL_read(ssl, buf, sizeof(buf)); // Receive message from server
        if (bytes > 0) {
            buf[bytes] = 0;
            printf("\nMESSAGE FROM SERVER: %s\n", buf);//Doesn't work
            printf("\nDEBUG: Received raw data [%s]\n", buf); // Debug output for raw data received
        } else if (bytes == 0) {
            printf("Server closed the connection\n");
            break;
        } else {
            ERR_print_errors_fp(stderr);
        }
    }
}

int main(int argc, char *argv[]) {
    SSL_CTX *ctx;
    int server;
    SSL *ssl;

    if (argc != 3) {
        printf("Usage: %s <hostname> <port>\n", argv[0]);
        exit(0);
    }

    SSL_library_init(); // Initialize OpenSSL
    ctx = InitCTX();    // Initialize SSL context
    server = OpenConnection(argv[1], atoi(argv[2])); // Establish connection
    ssl = SSL_new(ctx); // Create new SSL structure for the connection
    SSL_set_fd(ssl, server); // Associate the socket with the SSL structure

    if (SSL_connect(ssl) == FAIL) {
        ERR_print_errors_fp(stderr);
    } else {
        ClientChat(ssl, argv[1], atoi(argv[2])); // Start the chat session
    }

    SSL_free(ssl); // Free the SSL structure
    close(server); // Close the socket
    SSL_CTX_free(ctx); // Free the SSL context
    return 0;
}


