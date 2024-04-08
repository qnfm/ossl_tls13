#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#ifndef OPENSSL_NO_DEPRECATED_3_0
#define OPENSSL_NO_DEPRECATED_3_0
#endif


int main() {
    BIO *sbio, *bbio, *acpt, *out;
    SSL *ssl;
    int len;
    char tmpbuf[1024];

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());

    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Ensure the context is configured for TLS 1.3 only
//    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
//    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    SSL_CTX_set_ecdh_auto(ctx, 1);

    // Set the certificate and private key
    if (!SSL_CTX_use_certificate_file(ctx, "servercert.pem", SSL_FILETYPE_PEM)
        || !SSL_CTX_use_PrivateKey_file(ctx, "serverkey.pem", SSL_FILETYPE_PEM)
        || !SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Error setting up SSL_CTX\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

//    BIO *accept_bio = BIO_new_accept("4433");
    sbio = BIO_new_ssl(ctx, 0);
    BIO_get_ssl(sbio, &ssl);
    if (ssl == NULL) {
        fprintf(stderr, "Can't locate SSL pointer\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    bbio = BIO_new(BIO_f_buffer());
    sbio = BIO_push(bbio, sbio);
    acpt = BIO_new_accept("4433");
    BIO_set_accept_bios(acpt, sbio);
    out = BIO_new_fp(stdout, BIO_NOCLOSE);

/* First call to BIO_do_accept() sets up accept BIO */
    if (BIO_do_accept(acpt) <= 0) {
        fprintf(stderr, "Error setting up accept BIO\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }

/* Second call to BIO_do_accept() waits for incoming connection */
    if (BIO_do_accept(acpt) <= 0) {
        fprintf(stderr, "Error accepting connection\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    sbio = BIO_pop(acpt);
    BIO_free_all(acpt);

    if (BIO_do_handshake(sbio) <= 0) {
        fprintf(stderr, "Error in SSL handshake\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    BIO_puts(sbio, "HTTP/1.0 200 OK\r\nContent-type: text/plain\r\n\r\n");
    BIO_puts(sbio, "\r\nConnection Established\r\nRequest headers:\r\n");
    BIO_puts(sbio, "--------------------------------------------------\r\n");

    for (;;) {
        len = BIO_gets(sbio, tmpbuf, 1024);
        if (len <= 0)
            break;

//        BIO_write(sbio, tmpbuf, len);
        BIO_write(out, tmpbuf, len);
        /* Look for blank line signifying end of headers*/
        if (tmpbuf[0] == '\r' || tmpbuf[0] == '\n')
            break;
    }

    BIO_puts(sbio, "--------------------------------------------------\r\n");
    BIO_puts(sbio, "\r\n");
    BIO_flush(sbio);
    BIO_free_all(sbio);
}
//int create_socket(int port)
//{
//    int s;
//    struct sockaddr_in addr;
//
//    addr.sin_family = AF_INET;
//    addr.sin_port = htons(port);
//    addr.sin_addr.s_addr = htonl(INADDR_ANY);
//
//    s = socket(AF_INET, SOCK_STREAM, 0);
//    if (s < 0) {
//        perror("Unable to create socket");
//        exit(EXIT_FAILURE);
//    }
//
//    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
//        perror("Unable to bind");
//        exit(EXIT_FAILURE);
//    }
//
//    if (listen(s, 1) < 0) {
//        perror("Unable to listen");
//        exit(EXIT_FAILURE);
//    }
//
//    return s;
//}

//SSL_CTX *create_context()
//{
//    const SSL_METHOD *method;
//    SSL_CTX *ctx;
//
//    method = TLS_server_method();
//
//    ctx = SSL_CTX_new(method);
//    if (!ctx) {
//        perror("Unable to create SSL context");
//        ERR_print_errors_fp(stderr);
//        exit(EXIT_FAILURE);
//    }
//
//    return ctx;
//}
//
//void configure_context(SSL_CTX *ctx)
//{
//    /* Set the key and cert */
//    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
//        ERR_print_errors_fp(stderr);
//        exit(EXIT_FAILURE);
//    }
//
//    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0 ) {
//        ERR_print_errors_fp(stderr);
//        exit(EXIT_FAILURE);
//    }
//}
//
//int main(int argc, char **argv)
//{
//    int sock;
//    SSL_CTX *ctx;
//
//    /* Ignore broken pipe signals */
//    signal(SIGPIPE, SIG_IGN);
//
//    ctx = create_context();
//
//    configure_context(ctx);
//
//    sock = create_socket(4433);
//
//    /* Handle connections */
//    while(1) {
//        struct sockaddr_in addr;
//        unsigned int len = sizeof(addr);
//        SSL *ssl;
//        const char reply[] = "test\n";
//
//        int client = accept(sock, (struct sockaddr*)&addr, &len);
//        if (client < 0) {
//            perror("Unable to accept");
//            exit(EXIT_FAILURE);
//        }
//
//        ssl = SSL_new(ctx);
//        SSL_set_fd(ssl, client);
//
//        if (SSL_accept(ssl) <= 0) {
//            ERR_print_errors_fp(stderr);
//        } else {
//            SSL_write(ssl, reply, strlen(reply));
//            break;
//        }
//
//        SSL_shutdown(ssl);
//        SSL_free(ssl);
//        close(client);
//    }
//
//    close(sock);
//    SSL_CTX_free(ctx);
//}
