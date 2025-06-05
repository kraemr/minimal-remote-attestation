
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <tss2/tss2_tpm2_types.h>

extern int makeCredential(
    X509 *ek_cert,
    TPM2B_PUBLIC* publicKey,
    const uint8_t *secret, size_t secret_len,
    uint8_t **out_blob, size_t *out_blob_len,
    uint8_t **out_seed, size_t *out_seed_len
);