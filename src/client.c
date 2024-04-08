#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

int main() {
    BIO *sbio, *out;
    int len;
    char tmpbuf[1024];
    memset(tmpbuf, 0, sizeof(tmpbuf));
    SSL *ssl;
//    const SSL_METHOD* method = ();
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());

    if (!SSL_CTX_load_verify_locations(ctx, "rootcert.pem", NULL)) {
        perror("Error loading CA certificate");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Require server certificate verification
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    sbio = BIO_new_ssl_connect(ctx);
    BIO_get_ssl(sbio, &ssl);
    if (ssl == NULL) {
        fprintf(stderr, "Can't locate SSL pointer\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    BIO_set_conn_hostname(sbio, ":https");
    BIO_set_conn_port(sbio, "4433");
    out = BIO_new_fp(stdout, BIO_NOCLOSE);
    if (BIO_do_connect(sbio) <= 0) {
        fprintf(stderr, "Error connecting to server\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    BIO_puts(sbio, "GET / HTTP/1.0\n");
    for (;;) {
        len = BIO_read(sbio, tmpbuf, 1024);
        if (len <= 0)
            break;
        BIO_write(out, tmpbuf, len);

    }
    BIO_free_all(sbio);
    BIO_free(out);

}