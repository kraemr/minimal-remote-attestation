
/*#include "makecredential.h"
#define LABEL "IDENTITY"
#define AES_KEY_SIZE 16  // 128-bit
#define HMAC_KEY_SIZE 16
#define SEED_SIZE 32

// Simple TPM-style KDFa implementation for demonstration
int KDFa(const EVP_MD *md, const uint8_t *key, size_t key_len,
         const char *label, const uint8_t *contextU, size_t contextU_len,
         uint8_t *output, size_t output_len) {
    uint8_t counter[4] = {0, 0, 0, 1};
    uint8_t zero = 0;
    HMAC_CTX *ctx = HMAC_CTX_new();
    size_t generated = 0;

    if (!ctx) return 0;

    while (generated < output_len) {
        HMAC_Init_ex(ctx, key, key_len, md, NULL);
        HMAC_Update(ctx, counter, 4);
        HMAC_Update(ctx, (const uint8_t *)label, strlen(label));
        HMAC_Update(ctx, &zero, 1);
        HMAC_Update(ctx, contextU, contextU_len);
        HMAC_Update(ctx, counter, 4); // contextV: using counter again
        uint8_t hash[EVP_MAX_MD_SIZE];
        unsigned int len = 0;
        HMAC_Final(ctx, hash, &len);
        size_t to_copy = (output_len - generated < len) ? (output_len - generated) : len;
        memcpy(output + generated, hash, to_copy);
        generated += to_copy;
        counter[3]++;
    }

    HMAC_CTX_free(ctx);
    return 1;
}



int makeCredential(
    X509 *ek_cert,
    TPM2B_PUBLIC publicKey,
    const uint8_t *secret, size_t secret_len,
    uint8_t **out_blob, size_t *out_blob_len,
    uint8_t **out_seed, size_t *out_seed_len
) {
    EVP_PKEY *ek_pubkey = X509_get_pubkey(ek_cert);
    if (!ek_pubkey || EVP_PKEY_base_id(ek_pubkey) != EVP_PKEY_RSA)
        return 0;

    RSA *ek_rsa = EVP_PKEY_get1_RSA(ek_pubkey);
    EVP_PKEY_free(ek_pubkey);

    // Step 1: Generate random seed
    uint8_t seed[SEED_SIZE];
    RAND_bytes(seed, sizeof(seed));

    // Step 2: Encrypt seed using RSA-OAEP with label "IDENTITY"
    uint8_t *encrypted_seed = malloc(RSA_size(ek_rsa));
    int enc_seed_len = RSA_public_encrypt(
        sizeof(seed), seed, encrypted_seed,
        ek_rsa, RSA_PKCS1_OAEP_PADDING
    );
    if (enc_seed_len <= 0) {
        RSA_free(ek_rsa);
        free(encrypted_seed);
        return 0;
    }
    *out_seed = encrypted_seed;
    *out_seed_len = enc_seed_len;

    // Step 3: Derive keys from seed
    uint8_t sym_key[AES_KEY_SIZE];
    uint8_t hmac_key[HMAC_KEY_SIZE];
    KDFa(EVP_sha256(), seed, sizeof(seed), "STORAGE", ak_name, ak_name_len, sym_key, AES_KEY_SIZE);
    KDFa(EVP_sha256(), seed, sizeof(seed), "INTEGRITY", ak_name, ak_name_len, hmac_key, HMAC_KEY_SIZE);

    // Step 4: Encrypt secret using AES-CFB (with IV=zero)
    EVP_CIPHER_CTX *aes_ctx = EVP_CIPHER_CTX_new();
    uint8_t iv[16] = {0};
    uint8_t *enc_secret = malloc(secret_len);
    int outlen = 0, tmplen = 0;
    EVP_EncryptInit_ex(aes_ctx, EVP_aes_128_cfb(), NULL, sym_key, iv);
    EVP_EncryptUpdate(aes_ctx, enc_secret, &outlen, secret, secret_len);
    EVP_EncryptFinal_ex(aes_ctx, enc_secret + outlen, &tmplen);
    EVP_CIPHER_CTX_free(aes_ctx);

    size_t total_len = secret_len + ak_name_len;
    uint8_t *hmac_input = malloc(total_len);
    memcpy(hmac_input, enc_secret, secret_len);
    memcpy(hmac_input + secret_len, ak_name, ak_name_len);

    // Step 5: Create HMAC
    uint8_t hmac_out[EVP_MAX_MD_SIZE];
    unsigned int hmac_len;
    HMAC(EVP_sha256(), hmac_key, HMAC_KEY_SIZE, hmac_input, total_len, hmac_out, &hmac_len);
    free(hmac_input);

    // Step 6: Build credential blob (TPM2B_ID_OBJECT equivalent)
    *out_blob_len = 2 + hmac_len + 2 + secret_len;
    uint8_t *blob = malloc(*out_blob_len);
    uint8_t *ptr = blob;

    ptr[0] = (hmac_len >> 8) & 0xFF; ptr[1] = hmac_len & 0xFF;
    memcpy(ptr + 2, hmac_out, hmac_len);
    ptr += 2 + hmac_len;

    ptr[0] = (secret_len >> 8) & 0xFF; ptr[1] = secret_len & 0xFF;
    memcpy(ptr + 2, enc_secret, secret_len);
    *out_blob = blob;

    free(enc_secret);
    RSA_free(ek_rsa);
    return 1;
}*/