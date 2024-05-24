#include <gtk/gtk.h>
#include <glib/gunicode.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <getopt.h>
#include <string.h>
#include "dh.h"
#include "keys.h"

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

static GtkTextBuffer* tbuf;
static GtkEntry* message_entry;
static GtkTextView* tview;
static GtkTextMark* mark;

static pthread_t trecv;
void* recvMsg(void*);

static int listensock, sockfd;
static int isclient = 1;
unsigned char key[32]; // Assuming 256-bit key size

#define max(a, b) ({ typeof(a) _a = a; typeof(b) _b = b; _a > _b ? _a : _b; })

static void error(const char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}

int initServerNet(int port)
{
    int reuse = 1;
    struct sockaddr_in serv_addr;
    listensock = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(listensock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    if (listensock < 0)
        error("ERROR opening socket");
    bzero((char *)&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(port);
    if (bind(listensock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        error("ERROR on binding");
    fprintf(stderr, "listening on port %i...\n", port);
    listen(listensock, 1);
    socklen_t clilen;
    struct sockaddr_in cli_addr;
    sockfd = accept(listensock, (struct sockaddr *)&cli_addr, &clilen);
    if (sockfd < 0)
        error("error on accept");
    close(listensock);
    fprintf(stderr, "connection made, starting session...\n");
    return 0;
}

int initClientNet(char* hostname, int port)
{
    struct sockaddr_in serv_addr;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct hostent *server;
    if (sockfd < 0)
        error("ERROR opening socket");
    server = gethostbyname(hostname);
    if (server == NULL)
    {
        fprintf(stderr, "ERROR, no such host\n");
        exit(0);
    }
    bzero((char *)&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    serv_addr.sin_port = htons(port);
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        error("ERROR connecting");
    fprintf(stderr, "Connected to server...\n"); // Add this line
    return 0;
}

int shutdownNetwork()
{
    shutdown(sockfd, 2);
    unsigned char dummy[64];
    ssize_t r;
    do
    {
        r = recv(sockfd, dummy, 64, 0);
    } while (r != 0 && r != -1);
    close(sockfd);
    return 0;
}

static const char* usage =
"Usage: %s [OPTIONS]...\n"
"Secure chat (CCNY computer security project).\n\n"
"   -c, --connect HOST  Attempt a connection to HOST.\n"
"   -l, --listen        Listen for new connections.\n"
"   -p, --port    PORT  Listen or connect on PORT (defaults to 1337).\n"
"   -h, --help          show this message and exit.\n";

static void tsappend(char* message, char** tagnames, int ensurenewline)
{
    GtkTextIter t0;
    gtk_text_buffer_get_end_iter(tbuf, &t0);
    size_t len = g_utf8_strlen(message, -1);
    if (ensurenewline && message[len - 1] != '\n')
        message[len++] = '\n';
    gtk_text_buffer_insert(tbuf, &t0, message, len);
    GtkTextIter t1;
    gtk_text_buffer_get_end_iter(tbuf, &t1);
    t0 = t1;
    gtk_text_iter_backward_chars(&t0, len);
    if (tagnames)
    {
        char** tag = tagnames;
        while (*tag)
        {
            gtk_text_buffer_apply_tag_by_name(tbuf, *tag, &t0, &t1);
            tag++;
        }
    }
    if (!ensurenewline) return;
    gtk_text_buffer_add_mark(tbuf, mark, &t1);
    gtk_text_view_scroll_to_mark(tview, mark, 0.0, 0, 0.0, 0.0);
    gtk_text_buffer_delete_mark(tbuf, mark);
}

void sendMessage(GtkWidget* widget, gpointer data)
{
    char* tags[2] = { "self", NULL };
    tsappend("me: ", tags, 0);

    const gchar *message = gtk_entry_get_text(message_entry);

    // Debugging: print the message being sent
    printf("Sending message: %s\n", message);

    // Encryption and sending logic
    unsigned char encrypted[1024];
    int encrypted_len = encrypt_message((unsigned char*)message, strlen(message), encrypted, key);

    // Print the encrypted message in hex format
    printf("Encrypted message (length %d): ", encrypted_len);
    for (int i = 0; i < encrypted_len; ++i) {
        printf("%02x", encrypted[i]);
    }
    printf("\n");

    int bytes_sent = send(sockfd, encrypted, encrypted_len, 0);
    if (bytes_sent == -1) {
        perror("send");
    } else {
        printf("Sent %d bytes\n", bytes_sent);
    }

    tsappend((char*)message, NULL, 1);
    gtk_entry_set_text(message_entry, ""); // Clear the input buffer
}

gboolean shownewmessage(gpointer data);

void* recvMsg(void* arg)
{
    unsigned char buf[1024];
    int len;
    while ((len = recv(sockfd, buf, sizeof(buf), 0)) > 0)
    {
        printf("Received encrypted message (length %d): ", len); // Add this line
        for (int i = 0; i < len; ++i) {
            printf("%02x", buf[i]);
        }
        printf("\n");

        unsigned char decrypted[1024];
        int decrypted_len = decrypt_message(buf, len, decrypted, key);
        decrypted[decrypted_len] = '\0';

        // Debugging: print the message being received
        printf("Received decrypted message: %s\n", decrypted);

        char* message = g_strdup((char*)decrypted);
        g_idle_add(shownewmessage, message);
    }
    return NULL;
}

gboolean shownewmessage(gpointer data)
{
    char* tags[2] = { "friend", NULL };
    tsappend("friend: ", tags, 0);
    tsappend((char*)data, NULL, 1);

    // Debugging: print the message being displayed
    printf("Displaying message: %s\n", (char*)data);

    g_free(data);
    return FALSE;
}

int main(int argc, char *argv[])
{
    if (init("params") != 0) {
        fprintf(stderr, "could not read DH params from file 'params'\n");
        return 1;
    }

    static struct option long_opts[] = {
        {"connect",  required_argument, 0, 'c'},
        {"listen",   no_argument,       0, 'l'},
        {"port",     required_argument, 0, 'p'},
        {"help",     no_argument,       0, 'h'},
        {0,0,0,0}
    };

    char c;
    int opt_index = 0;
    int port = 1337;
    char hostname[HOST_NAME_MAX+1] = "localhost";
    hostname[HOST_NAME_MAX] = 0;

    while ((c = getopt_long(argc, argv, "c:lp:h", long_opts, &opt_index)) != -1) {
        switch (c) {
            case 'c':
                if (strnlen(optarg,HOST_NAME_MAX))
                    strncpy(hostname,optarg,HOST_NAME_MAX);
                break;
            case 'l':
                isclient = 0;
                break;
            case 'p':
                port = atoi(optarg);
                break;
            case 'h':
                printf(usage,argv[0]);
                return 0;
            case '?':
                printf(usage,argv[0]);
                return 1;
        }
    }

    if (isclient) {
        initClientNet(hostname,port);
    } else {
        initServerNet(port);
    }

    GtkBuilder* builder;
    GObject* window;
    GObject* button;
    GObject* transcript;
    GObject* message;
    GError* error = NULL;
    gtk_init(&argc, &argv);
    builder = gtk_builder_new();
    if (gtk_builder_add_from_file(builder,"layout.ui",&error) == 0) {
        g_printerr("Error reading %s\n", error->message);
        g_clear_error(&error);
        return 1;
    }
    mark  = gtk_text_mark_new(NULL,TRUE);
    window = gtk_builder_get_object(builder,"window");
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
    transcript = gtk_builder_get_object(builder, "transcript");
    tview = GTK_TEXT_VIEW(transcript);
    message = gtk_builder_get_object(builder, "message");
    tbuf = gtk_text_view_get_buffer(tview);
    message_entry = GTK_ENTRY(message);
    button = gtk_builder_get_object(builder, "send");
    g_signal_connect(button, "clicked", G_CALLBACK(sendMessage), message_entry);
    gtk_widget_grab_focus(GTK_WIDGET(message));
    GtkCssProvider* css = gtk_css_provider_new();
    gtk_css_provider_load_from_path(css,"colors.css",NULL);
    gtk_style_context_add_provider_for_screen(gdk_screen_get_default(),
            GTK_STYLE_PROVIDER(css),
            GTK_STYLE_PROVIDER_PRIORITY_USER);

    gtk_text_buffer_create_tag(tbuf,"status","foreground","#657b83","font","italic",NULL);
    gtk_text_buffer_create_tag(tbuf,"friend","foreground","#6c71c4","font","bold",NULL);
    gtk_text_buffer_create_tag(tbuf,"self","foreground","#268bd2","font","bold",NULL);

    if (pthread_create(&trecv,0,recvMsg,0)) {
        fprintf(stderr, "Failed to create update thread.\n");
    }

    gtk_main();
    shutdownNetwork();
    return 0;
}




/*
#include <gtk/gtk.h>
#include <glib/gunicode.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <getopt.h>
#include <string.h>
#include "dh.h"
#include "keys.h"

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

static GtkTextBuffer* tbuf;
static GtkEntry* message_entry;
static GtkTextView* tview;
static GtkTextMark* mark;

static pthread_t trecv;
void* recvMsg(void*);

static int listensock, sockfd;
static int isclient = 1;
unsigned char key[32]; // Assuming 256-bit key size

#define max(a, b) ({ typeof(a) _a = a; typeof(b) _b = b; _a > _b ? _a : _b; })

static void error(const char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}

int initServerNet(int port)
{
    int reuse = 1;
    struct sockaddr_in serv_addr;
    listensock = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(listensock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    if (listensock < 0)
        error("ERROR opening socket");
    bzero((char *)&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(port);
    if (bind(listensock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        error("ERROR on binding");
    fprintf(stderr, "listening on port %i...\n", port);
    listen(listensock, 1);
    socklen_t clilen;
    struct sockaddr_in cli_addr;
    sockfd = accept(listensock, (struct sockaddr *)&cli_addr, &clilen);
    if (sockfd < 0)
        error("error on accept");
    close(listensock);
    fprintf(stderr, "connection made, starting session...\n");
    return 0;
}

int initClientNet(char* hostname, int port)
{
    struct sockaddr_in serv_addr;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct hostent *server;
    if (sockfd < 0)
        error("ERROR opening socket");
    server = gethostbyname(hostname);
    if (server == NULL)
    {
        fprintf(stderr, "ERROR, no such host\n");
        exit(0);
    }
    bzero((char *)&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    serv_addr.sin_port = htons(port);
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        error("ERROR connecting");
    fprintf(stderr, "Connected to server...\n"); // Add this line
    return 0;
}

int shutdownNetwork()
{
    shutdown(sockfd, 2);
    unsigned char dummy[64];
    ssize_t r;
    do
    {
        r = recv(sockfd, dummy, 64, 0);
    } while (r != 0 && r != -1);
    close(sockfd);
    return 0;
}

static const char* usage =
"Usage: %s [OPTIONS]...\n"
"Secure chat (CCNY computer security project).\n\n"
"   -c, --connect HOST  Attempt a connection to HOST.\n"
"   -l, --listen        Listen for new connections.\n"
"   -p, --port    PORT  Listen or connect on PORT (defaults to 1337).\n"
"   -h, --help          show this message and exit.\n";

static void tsappend(char* message, char** tagnames, int ensurenewline)
{
    GtkTextIter t0;
    gtk_text_buffer_get_end_iter(tbuf, &t0);
    size_t len = g_utf8_strlen(message, -1);
    if (ensurenewline && message[len - 1] != '\n')
        message[len++] = '\n';
    gtk_text_buffer_insert(tbuf, &t0, message, len);
    GtkTextIter t1;
    gtk_text_buffer_get_end_iter(tbuf, &t1);
    t0 = t1;
    gtk_text_iter_backward_chars(&t0, len);
    if (tagnames)
    {
        char** tag = tagnames;
        while (*tag)
        {
            gtk_text_buffer_apply_tag_by_name(tbuf, *tag, &t0, &t1);
            tag++;
        }
    }
    if (!ensurenewline) return;
    gtk_text_buffer_add_mark(tbuf, mark, &t1);
    gtk_text_view_scroll_to_mark(tview, mark, 0.0, 0, 0.0, 0.0);
    gtk_text_buffer_delete_mark(tbuf, mark);
}

void sendMessage(GtkWidget* widget, gpointer data)
{
    char* tags[2] = { "self", NULL };
    tsappend("me: ", tags, 0);

    const gchar *message = gtk_entry_get_text(message_entry);

    // Debugging: print the message being sent
    printf("Sending message: %s\n", message);

    // Encryption and sending logic
    unsigned char encrypted[1024];
    int encrypted_len = encrypt_message((unsigned char*)message, strlen(message), encrypted, key);
    if (send(sockfd, encrypted, encrypted_len, 0) == -1) {
        perror("send");
    }

    tsappend((char*)message, NULL, 1);
    gtk_entry_set_text(message_entry, ""); // Clear the input buffer
}

gboolean shownewmessage(gpointer data);

void* recvMsg(void* arg)
{
    unsigned char buf[1024];
    int len;
    while ((len = recv(sockfd, buf, sizeof(buf), 0)) > 0)
    {
        printf("Received encrypted message\n"); // Add this line
        unsigned char decrypted[1024];
        int decrypted_len = decrypt_message(buf, len, decrypted, key);
        decrypted[decrypted_len] = '\0';

        // Debugging: print the message being received
        printf("Received decrypted message: %s\n", decrypted);

        char* message = g_strdup((char*)decrypted);
        g_idle_add(shownewmessage, message);
    }
    return NULL;
}

gboolean shownewmessage(gpointer data)
{
    char* tags[2] = { "friend", NULL };
    tsappend("friend: ", tags, 0);
    tsappend((char*)data, NULL, 1);

    // Debugging: print the message being displayed
    printf("Displaying message: %s\n", (char*)data);

    g_free(data);
    return FALSE;
}

int main(int argc, char *argv[])
{
    if (init("params") != 0) {
        fprintf(stderr, "could not read DH params from file 'params'\n");
        return 1;
    }

    static struct option long_opts[] = {
        {"connect",  required_argument, 0, 'c'},
        {"listen",   no_argument,       0, 'l'},
        {"port",     required_argument, 0, 'p'},
        {"help",     no_argument,       0, 'h'},
        {0,0,0,0}
    };

    char c;
    int opt_index = 0;
    int port = 1337;
    char hostname[HOST_NAME_MAX+1] = "localhost";
    hostname[HOST_NAME_MAX] = 0;

    while ((c = getopt_long(argc, argv, "c:lp:h", long_opts, &opt_index)) != -1) {
        switch (c) {
            case 'c':
                if (strnlen(optarg,HOST_NAME_MAX))
                    strncpy(hostname,optarg,HOST_NAME_MAX);
                break;
            case 'l':
                isclient = 0;
                break;
            case 'p':
                port = atoi(optarg);
                break;
            case 'h':
                printf(usage,argv[0]);
                return 0;
            case '?':
                printf(usage,argv[0]);
                return 1;
        }
    }

    if (isclient) {
        initClientNet(hostname,port);
    } else {
        initServerNet(port);
    }

    GtkBuilder* builder;
    GObject* window;
    GObject* button;
    GObject* transcript;
    GObject* message;
    GError* error = NULL;
    gtk_init(&argc, &argv);
    builder = gtk_builder_new();
    if (gtk_builder_add_from_file(builder,"layout.ui",&error) == 0) {
        g_printerr("Error reading %s\n", error->message);
        g_clear_error(&error);
        return 1;
    }
    mark  = gtk_text_mark_new(NULL,TRUE);
    window = gtk_builder_get_object(builder,"window");
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
    transcript = gtk_builder_get_object(builder, "transcript");
    tview = GTK_TEXT_VIEW(transcript);
    message = gtk_builder_get_object(builder, "message");
    tbuf = gtk_text_view_get_buffer(tview);
    message_entry = GTK_ENTRY(message);
    button = gtk_builder_get_object(builder, "send");
    g_signal_connect(button, "clicked", G_CALLBACK(sendMessage), message_entry);
    gtk_widget_grab_focus(GTK_WIDGET(message));
    GtkCssProvider* css = gtk_css_provider_new();
    gtk_css_provider_load_from_path(css,"colors.css",NULL);
    gtk_style_context_add_provider_for_screen(gdk_screen_get_default(),
            GTK_STYLE_PROVIDER(css),
            GTK_STYLE_PROVIDER_PRIORITY_USER);

    gtk_text_buffer_create_tag(tbuf,"status","foreground","#657b83","font","italic",NULL);
    gtk_text_buffer_create_tag(tbuf,"friend","foreground","#6c71c4","font","bold",NULL);
    gtk_text_buffer_create_tag(tbuf,"self","foreground","#268bd2","font","bold",NULL);

    if (pthread_create(&trecv,0,recvMsg,0)) {
        fprintf(stderr, "Failed to create update thread.\n");
    }

    gtk_main();
    shutdownNetwork();
    return 0;
}


*/


/*
#include <gtk/gtk.h>
#include <glib/gunicode.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <getopt.h>
#include <string.h>
#include "dh.h"
#include "keys.h"

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

static GtkTextBuffer* tbuf;
static GtkEntry* message_entry;
static GtkTextView* tview;
static GtkTextMark* mark;

static pthread_t trecv;
void* recvMsg(void*);

static int listensock, sockfd;
static int isclient = 1;
unsigned char key[32]; // Assuming 256-bit key size

#define max(a, b) ({ typeof(a) _a = a; typeof(b) _b = b; _a > _b ? _a : _b; })

static void error(const char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}

int initServerNet(int port)
{
    int reuse = 1;
    struct sockaddr_in serv_addr;
    listensock = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(listensock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    if (listensock < 0)
        error("ERROR opening socket");
    bzero((char *)&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(port);
    if (bind(listensock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        error("ERROR on binding");
    fprintf(stderr, "listening on port %i...\n", port);
    listen(listensock, 1);
    socklen_t clilen;
    struct sockaddr_in cli_addr;
    sockfd = accept(listensock, (struct sockaddr *)&cli_addr, &clilen);
    if (sockfd < 0)
        error("error on accept");
    close(listensock);
    fprintf(stderr, "connection made, starting session...\n");
    return 0;
}

int initClientNet(char* hostname, int port)
{
    struct sockaddr_in serv_addr;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct hostent *server;
    if (sockfd < 0)
        error("ERROR opening socket");
    server = gethostbyname(hostname);
    if (server == NULL)
    {
        fprintf(stderr, "ERROR, no such host\n");
        exit(0);
    }
    bzero((char *)&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    serv_addr.sin_port = htons(port);
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        error("ERROR connecting");
    return 0;
}

int shutdownNetwork()
{
    shutdown(sockfd, 2);
    unsigned char dummy[64];
    ssize_t r;
    do
    {
        r = recv(sockfd, dummy, 64, 0);
    } while (r != 0 && r != -1);
    close(sockfd);
    return 0;
}

static const char* usage =
"Usage: %s [OPTIONS]...\n"
"Secure chat (CCNY computer security project).\n\n"
"   -c, --connect HOST  Attempt a connection to HOST.\n"
"   -l, --listen        Listen for new connections.\n"
"   -p, --port    PORT  Listen or connect on PORT (defaults to 1337).\n"
"   -h, --help          show this message and exit.\n";

static void tsappend(char* message, char** tagnames, int ensurenewline)
{
    GtkTextIter t0;
    gtk_text_buffer_get_end_iter(tbuf, &t0);
    size_t len = g_utf8_strlen(message, -1);
    if (ensurenewline && message[len - 1] != '\n')
        message[len++] = '\n';
    gtk_text_buffer_insert(tbuf, &t0, message, len);
    GtkTextIter t1;
    gtk_text_buffer_get_end_iter(tbuf, &t1);
    t0 = t1;
    gtk_text_iter_backward_chars(&t0, len);
    if (tagnames)
    {
        char** tag = tagnames;
        while (*tag)
        {
            gtk_text_buffer_apply_tag_by_name(tbuf, *tag, &t0, &t1);
            tag++;
        }
    }
    if (!ensurenewline) return;
    gtk_text_buffer_add_mark(tbuf, mark, &t1);
    gtk_text_view_scroll_to_mark(tview, mark, 0.0, 0, 0.0, 0.0);
    gtk_text_buffer_delete_mark(tbuf, mark);
}

void sendMessage(GtkWidget* widget, gpointer data)
{
    char* tags[2] = { "self", NULL };
    tsappend("me: ", tags, 0);

    const gchar *message = gtk_entry_get_text(message_entry);

    // Debugging: print the message being sent
    printf("Sending message: %s\n", message);

    // Encryption and sending logic
    unsigned char encrypted[1024];
    int encrypted_len = encrypt_message((unsigned char*)message, strlen(message), encrypted, key);
    if (send(sockfd, encrypted, encrypted_len, 0) == -1) {
        perror("send");
    }

    tsappend((char*)message, NULL, 1);
    gtk_entry_set_text(message_entry, ""); // Clear the input buffer
}

gboolean shownewmessage(gpointer data);

void* recvMsg(void* arg)
{
    unsigned char buf[1024];
    int len;
    while ((len = recv(sockfd, buf, sizeof(buf), 0)) > 0)
    {
        unsigned char decrypted[1024];
        int decrypted_len = decrypt_message(buf, len, decrypted, key);
        decrypted[decrypted_len] = '\0';

        // Debugging: print the message being received
        printf("Received message: %s\n", decrypted);

        char* message = g_strdup((char*)decrypted);
        g_idle_add(shownewmessage, message);
    }
    return NULL;
}

gboolean shownewmessage(gpointer data)
{
    char* tags[2] = { "friend", NULL };
    tsappend("friend: ", tags, 0);
    tsappend((char*)data, NULL, 1);

    // Debugging: print the message being displayed
    printf("Displaying message: %s\n", (char*)data);

    g_free(data);
    return FALSE;
}

int main(int argc, char *argv[])
{
    if (init("params") != 0) {
        fprintf(stderr, "could not read DH params from file 'params'\n");
        return 1;
    }

    static struct option long_opts[] = {
        {"connect",  required_argument, 0, 'c'},
        {"listen",   no_argument,       0, 'l'},
        {"port",     required_argument, 0, 'p'},
        {"help",     no_argument,       0, 'h'},
        {0,0,0,0}
    };

    char c;
    int opt_index = 0;
    int port = 1337;
    char hostname[HOST_NAME_MAX+1] = "localhost";
    hostname[HOST_NAME_MAX] = 0;

    while ((c = getopt_long(argc, argv, "c:lp:h", long_opts, &opt_index)) != -1) {
        switch (c) {
            case 'c':
                if (strnlen(optarg,HOST_NAME_MAX))
                    strncpy(hostname,optarg,HOST_NAME_MAX);
                break;
            case 'l':
                isclient = 0;
                break;
            case 'p':
                port = atoi(optarg);
                break;
            case 'h':
                printf(usage,argv[0]);
                return 0;
            case '?':
                printf(usage,argv[0]);
                return 1;
        }
    }

    if (isclient) {
        initClientNet(hostname,port);
    } else {
        initServerNet(port);
    }

    GtkBuilder* builder;
    GObject* window;
    GObject* button;
    GObject* transcript;
    GObject* message;
    GError* error = NULL;
    gtk_init(&argc, &argv);
    builder = gtk_builder_new();
    if (gtk_builder_add_from_file(builder,"layout.ui",&error) == 0) {
        g_printerr("Error reading %s\n", error->message);
        g_clear_error(&error);
        return 1;
    }
    mark  = gtk_text_mark_new(NULL,TRUE);
    window = gtk_builder_get_object(builder,"window");
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
    transcript = gtk_builder_get_object(builder, "transcript");
    tview = GTK_TEXT_VIEW(transcript);
    message = gtk_builder_get_object(builder, "message");
    tbuf = gtk_text_view_get_buffer(tview);
    message_entry = GTK_ENTRY(message);
    button = gtk_builder_get_object(builder, "send");
    g_signal_connect(button, "clicked", G_CALLBACK(sendMessage), message_entry);
    gtk_widget_grab_focus(GTK_WIDGET(message));
    GtkCssProvider* css = gtk_css_provider_new();
    gtk_css_provider_load_from_path(css,"colors.css",NULL);
    gtk_style_context_add_provider_for_screen(gdk_screen_get_default(),
            GTK_STYLE_PROVIDER(css),
            GTK_STYLE_PROVIDER_PRIORITY_USER);

    gtk_text_buffer_create_tag(tbuf,"status","foreground","#657b83","font","italic",NULL);
    gtk_text_buffer_create_tag(tbuf,"friend","foreground","#6c71c4","font","bold",NULL);
    gtk_text_buffer_create_tag(tbuf,"self","foreground","#268bd2","font","bold",NULL);

    if (pthread_create(&trecv,0,recvMsg,0)) {
        fprintf(stderr, "Failed to create update thread.\n");
    }

    gtk_main();
    shutdownNetwork();
    return 0;
}

*/





/*
#include <gtk/gtk.h>
#include <glib/gunicode.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <getopt.h>
#include <string.h>
#include "dh.h"
#include "keys.h"

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

static GtkTextBuffer* tbuf;
static GtkEntry* message_entry;
static GtkTextView* tview;
static GtkTextMark* mark;

static pthread_t trecv;
void* recvMsg(void*);

static int listensock, sockfd;
static int isclient = 1;
unsigned char key[32]; // Assuming 256-bit key size

#define max(a, b) ({ typeof(a) _a = a; typeof(b) _b = b; _a > _b ? _a : _b; })

static void error(const char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}

int initServerNet(int port)
{
    int reuse = 1;
    struct sockaddr_in serv_addr;
    listensock = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(listensock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    if (listensock < 0)
        error("ERROR opening socket");
    bzero((char *)&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(port);
    if (bind(listensock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        error("ERROR on binding");
    fprintf(stderr, "listening on port %i...\n", port);
    listen(listensock, 1);
    socklen_t clilen;
    struct sockaddr_in cli_addr;
    sockfd = accept(listensock, (struct sockaddr *)&cli_addr, &clilen);
    if (sockfd < 0)
        error("error on accept");
    close(listensock);
    fprintf(stderr, "connection made, starting session...\n");
    return 0;
}

int initClientNet(char* hostname, int port)
{
    struct sockaddr_in serv_addr;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct hostent *server;
    if (sockfd < 0)
        error("ERROR opening socket");
    server = gethostbyname(hostname);
    if (server == NULL)
    {
        fprintf(stderr, "ERROR, no such host\n");
        exit(0);
    }
    bzero((char *)&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    serv_addr.sin_port = htons(port);
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        error("ERROR connecting");
    return 0;
}

int shutdownNetwork()
{
    shutdown(sockfd, 2);
    unsigned char dummy[64];
    ssize_t r;
    do
    {
        r = recv(sockfd, dummy, 64, 0);
    } while (r != 0 && r != -1);
    close(sockfd);
    return 0;
}

static const char* usage =
"Usage: %s [OPTIONS]...\n"
"Secure chat (CCNY computer security project).\n\n"
"   -c, --connect HOST  Attempt a connection to HOST.\n"
"   -l, --listen        Listen for new connections.\n"
"   -p, --port    PORT  Listen or connect on PORT (defaults to 1337).\n"
"   -h, --help          show this message and exit.\n";

static void tsappend(char* message, char** tagnames, int ensurenewline)
{
    GtkTextIter t0;
    gtk_text_buffer_get_end_iter(tbuf, &t0);
    size_t len = g_utf8_strlen(message, -1);
    if (ensurenewline && message[len - 1] != '\n')
        message[len++] = '\n';
    gtk_text_buffer_insert(tbuf, &t0, message, len);
    GtkTextIter t1;
    gtk_text_buffer_get_end_iter(tbuf, &t1);
    t0 = t1;
    gtk_text_iter_backward_chars(&t0, len);
    if (tagnames)
    {
        char** tag = tagnames;
        while (*tag)
        {
            gtk_text_buffer_apply_tag_by_name(tbuf, *tag, &t0, &t1);
            tag++;
        }
    }
    if (!ensurenewline) return;
    gtk_text_buffer_add_mark(tbuf, mark, &t1);
    gtk_text_view_scroll_to_mark(tview, mark, 0.0, 0, 0.0, 0.0);
    gtk_text_buffer_delete_mark(tbuf, mark);
}

void sendMessage(GtkWidget* widget, gpointer data)
{
    char* tags[2] = { "self", NULL };
    tsappend("me: ", tags, 0);

    const gchar *message = gtk_entry_get_text(message_entry);

    // Debugging: print the message being sent
    printf("Sending message: %s\n", message);

    // Encryption and sending logic
    unsigned char encrypted[1024];
    int encrypted_len = encrypt_message((unsigned char*)message, strlen(message), encrypted, key);
    if (send(sockfd, encrypted, encrypted_len, 0) == -1) {
        perror("send");
    }

    tsappend((char*)message, NULL, 1);
    gtk_entry_set_text(message_entry, ""); // Clear the input buffer
}

gboolean shownewmessage(gpointer data);

void* recvMsg(void* arg)
{
    unsigned char buf[1024];
    int len;
    while ((len = recv(sockfd, buf, sizeof(buf), 0)) > 0)
    {
        unsigned char decrypted[1024];
        int decrypted_len = decrypt_message(buf, len, decrypted, key);
        decrypted[decrypted_len] = '\0';

        // Debugging: print the message being received
        printf("Received message: %s\n", decrypted);

        char* message = g_strdup((char*)decrypted);
        g_idle_add(shownewmessage, message);
    }
    return NULL;
}

gboolean shownewmessage(gpointer data)
{
    char* tags[2] = { "friend", NULL };
    tsappend("friend: ", tags, 0);
    tsappend((char*)data, NULL, 1);

    // Debugging: print the message being displayed
    printf("Displaying message: %s\n", (char*)data);

    g_free(data);
    return FALSE;
}

int main(int argc, char *argv[])
{
    if (init("params") != 0) {
        fprintf(stderr, "could not read DH params from file 'params'\n");
        return 1;
    }

    static struct option long_opts[] = {
        {"connect",  required_argument, 0, 'c'},
        {"listen",   no_argument,       0, 'l'},
        {"port",     required_argument, 0, 'p'},
        {"help",     no_argument,       0, 'h'},
        {0,0,0,0}
    };

    char c;
    int opt_index = 0;
    int port = 1337;
    char hostname[HOST_NAME_MAX+1] = "localhost";
    hostname[HOST_NAME_MAX] = 0;

    while ((c = getopt_long(argc, argv, "c:lp:h", long_opts, &opt_index)) != -1) {
        switch (c) {
            case 'c':
                if (strnlen(optarg,HOST_NAME_MAX))
                    strncpy(hostname,optarg,HOST_NAME_MAX);
                break;
            case 'l':
                isclient = 0;
                break;
            case 'p':
                port = atoi(optarg);
                break;
            case 'h':
                printf(usage,argv[0]);
                return 0;
            case '?':
                printf(usage,argv[0]);
                return 1;
        }
    }

    if (isclient) {
        initClientNet(hostname,port);
    } else {
        initServerNet(port);
    }

    GtkBuilder* builder;
    GObject* window;
    GObject* button;
    GObject* transcript;
    GObject* message;
    GError* error = NULL;
    gtk_init(&argc, &argv);
    builder = gtk_builder_new();
    if (gtk_builder_add_from_file(builder,"layout.ui",&error) == 0) {
        g_printerr("Error reading %s\n", error->message);
        g_clear_error(&error);
        return 1;
    }
    mark  = gtk_text_mark_new(NULL,TRUE);
    window = gtk_builder_get_object(builder,"window");
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
    transcript = gtk_builder_get_object(builder, "transcript");
    tview = GTK_TEXT_VIEW(transcript);
    message = gtk_builder_get_object(builder, "message");
    tbuf = gtk_text_view_get_buffer(tview);
    message_entry = GTK_ENTRY(message);
    button = gtk_builder_get_object(builder, "send");
    g_signal_connect(button, "clicked", G_CALLBACK(sendMessage), message_entry);
    gtk_widget_grab_focus(GTK_WIDGET(message));
    GtkCssProvider* css = gtk_css_provider_new();
    gtk_css_provider_load_from_path(css,"colors.css",NULL);
    gtk_style_context_add_provider_for_screen(gdk_screen_get_default(),
            GTK_STYLE_PROVIDER(css),
            GTK_STYLE_PROVIDER_PRIORITY_USER);

    gtk_text_buffer_create_tag(tbuf,"status","foreground","#657b83","font","italic",NULL);
    gtk_text_buffer_create_tag(tbuf,"friend","foreground","#6c71c4","font","bold",NULL);
    gtk_text_buffer_create_tag(tbuf,"self","foreground","#268bd2","font","bold",NULL);

    if (pthread_create(&trecv,0,recvMsg,0)) {
        fprintf(stderr, "Failed to create update thread.\n");
    }

    gtk_main();
    shutdownNetwork();
    return 0;
}

*/