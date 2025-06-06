#include <openssl/hmac.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_sys.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>

#define AES_KEY_SIZE 16
#define AES_BLOCK_SIZE 16
#define SEED_SIZE 32
#define HMAC_KEY_SIZE 32
#define ENCRYPT_KEY_SIZE 16
#define IDENTITY_LABEL "IDENTITY"



bool kdfa(TPMI_ALG_HASH hashAlg,
          const uint8_t *key, size_t key_len,
          const char *label,
          const uint8_t *contextU, size_t contextU_len,
          const uint8_t *contextV, size_t contextV_len,
          uint8_t *output, size_t bits) {
    const EVP_MD *md = NULL;
    size_t hash_len;

    switch (hashAlg) {
        case TPM2_ALG_SHA256: md = EVP_sha256(); hash_len = 32; break;
        case TPM2_ALG_SHA1:   md = EVP_sha1();   hash_len = 20; break;
        default: return false;
    }

    size_t bytes = (bits + 7) / 8;
    uint8_t counter_be[4] = {0, 0, 0, 1};
    size_t written = 0;

    while (written < bytes) {
        HMAC_CTX *hmac = HMAC_CTX_new();
        HMAC_Init_ex(hmac, key, key_len, md, NULL);
        HMAC_Update(hmac, counter_be, 4);
        HMAC_Update(hmac, (const uint8_t *)label, strlen(label) + 1);
        if (contextU) HMAC_Update(hmac, contextU, contextU_len);
        if (contextV) HMAC_Update(hmac, contextV, contextV_len);

        uint8_t digest[EVP_MAX_MD_SIZE];
        unsigned int len;
        HMAC_Final(hmac, digest, &len);
        HMAC_CTX_free(hmac);

        size_t to_copy = (written + len > bytes) ? (bytes - written) : len;
        memcpy(output + written, digest, to_copy);
        written += to_copy;
        counter_be[3]++;
    }

    return true;
}


TPM2_RC computeAkName(const TPM2B_PUBLIC *public, TPM2B_NAME *name_out) {
    if (!public || !name_out) return TSS2_ESYS_RC_BAD_REFERENCE;

    // 1. Marshal TPMT_PUBLIC
    uint8_t buffer[1024];
    size_t offset = 0;
    TSS2_RC rc = Tss2_MU_TPMT_PUBLIC_Marshal(&public->publicArea, buffer, sizeof(buffer), &offset);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Error marshaling TPMT_PUBLIC: 0x%x\n", rc);
        return rc;
    }

    // 2. Determine hash algorithm
    TPMI_ALG_HASH nameAlg = public->publicArea.nameAlg;
    const EVP_MD *md = NULL;
    switch (nameAlg) {
        case TPM2_ALG_SHA1:   md = EVP_sha1();   break;
        case TPM2_ALG_SHA256: md = EVP_sha256(); break;
        case TPM2_ALG_SHA384: md = EVP_sha384(); break;
        case TPM2_ALG_SHA512: md = EVP_sha512(); break;
        default:
            fprintf(stderr, "Unsupported name algorithm: 0x%x\n", nameAlg);
            return TSS2_ESYS_RC_BAD_VALUE;
    }

    // 3. Compute hash
    uint8_t digest[64];
    unsigned int digest_len = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, md, NULL);
    EVP_DigestUpdate(ctx, buffer, offset);
    EVP_DigestFinal_ex(ctx, digest, &digest_len);
    EVP_MD_CTX_free(ctx);

    // 4. Assemble name = nameAlg (big endian) || digest
    name_out->size = digest_len + 2;
    name_out->name[0] = (nameAlg >> 8) & 0xFF;
    name_out->name[1] = nameAlg & 0xFF;
    memcpy(&name_out->name[2], digest, digest_len);

    return TPM2_RC_SUCCESS;
}