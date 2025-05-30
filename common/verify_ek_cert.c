#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include <stdio.h>

X509* loadPemX509FromMemory(const uint8_t* pem_buf, size_t len) {
    BIO* bio = BIO_new_mem_buf(pem_buf, len);
    if (!bio) return NULL;
    X509* cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return cert;
}

int32_t verifyEkCertificate(const char *root_bundle_path, uint8_t* ekCertificate, size_t ekCertLen ) {    

    X509 *ek_cert = loadPemX509FromMemory(ekCertificate,ekCertLen);

    // Create a certificate store
    X509_STORE *store = X509_STORE_new();
    if (!store) {
        fprintf(stderr, "Failed to create X509_STORE\n");
        X509_free(ek_cert);
        return 1;
    }

    // Load root certificates into store
    if (!X509_STORE_load_locations(store, root_bundle_path, NULL)) {
        fprintf(stderr, "Failed to load root cert bundle\n");
        X509_STORE_free(store);
        X509_free(ek_cert);
        return 1;
    }

    // Create a verification context
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create X509_STORE_CTX\n");
        X509_STORE_free(store);
        X509_free(ek_cert);
        return 1;
    }

    // Initialize context for verification
    if (!X509_STORE_CTX_init(ctx, store, ek_cert, NULL)) {
        fprintf(stderr, "Failed to initialize verify context\n");
        X509_STORE_CTX_free(ctx);
        X509_STORE_free(store);
        X509_free(ek_cert);
        return 1;
    }

    // Verify EK certificate
    int result = X509_verify_cert(ctx);
    if (result == 1) {
        printf("✅ EK certificate verified successfully!\n");
    } else {
        int err = X509_STORE_CTX_get_error(ctx);
        fprintf(stderr, "❌ Verification failed: %s\n", X509_verify_cert_error_string(err));
    }

    // Cleanup
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    X509_free(ek_cert);
    return result;
}