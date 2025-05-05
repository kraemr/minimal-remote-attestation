#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/types.h>
#include <stddef.h>
#include <stdio.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_tpm2_types.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>


#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <tss2/tss2_tpm2_types.h>

#define DEFAULT_RSA_EXPONENT 65537

EVP_PKEY* convertTpm2bPublicToEvp(const TPM2B_PUBLIC *pub) {
    if (pub->publicArea.type == TPM2_ALG_RSA) {
        const TPM2B_PUBLIC_KEY_RSA *rsa = &pub->publicArea.unique.rsa;
        BIGNUM *n = BN_bin2bn(rsa->buffer, rsa->size, NULL);
        BIGNUM *e = BN_new(); BN_set_word(e, DEFAULT_RSA_EXPONENT);
        RSA *rsa_key = RSA_new();
        RSA_set0_key(rsa_key, n, e, NULL);
        EVP_PKEY *pkey = EVP_PKEY_new();
        EVP_PKEY_assign_RSA(pkey, rsa_key);
        return pkey;

    } else if (pub->publicArea.type == TPM2_ALG_ECC) {
        const TPM2B_ECC_PARAMETER *x = &pub->publicArea.unique.ecc.x;
        const TPM2B_ECC_PARAMETER *y = &pub->publicArea.unique.ecc.y;

        int nid = NID_X9_62_prime256v1; // TPM2_ECC_NIST_P256
        EC_KEY *ec = EC_KEY_new_by_curve_name(nid);
        BIGNUM *bn_x = BN_bin2bn(x->buffer, x->size, NULL);
        BIGNUM *bn_y = BN_bin2bn(y->buffer, y->size, NULL);
        EC_KEY_set_public_key_affine_coordinates(ec, bn_x, bn_y);
        EVP_PKEY *pkey = EVP_PKEY_new();
        EVP_PKEY_assign_EC_KEY(pkey, ec);
        return pkey;
    }

    return NULL;
}

int verifyQuote(EVP_PKEY *pkey, const uint8_t *quote_data, size_t quote_size,const uint8_t *sig, size_t sig_len) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) return 0;
    int ok = EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pkey) == 1 &&
             EVP_DigestVerifyUpdate(mdctx, quote_data, quote_size) == 1 &&
             EVP_DigestVerifyFinal(mdctx, sig, sig_len) == 1;
    EVP_MD_CTX_free(mdctx);
    return ok;
}

bool verifyQuoteSignature(TPM2B_PUBLIC pub_key, TPM2B_ATTEST quote, TPMT_SIGNATURE signature) {
    EVP_PKEY *pkey = convertTpm2bPublicToEvp(&pub_key);

    
    int verified = verifyQuote(
        pkey,
        quote.attestationData, quote.size,
        signature.signature.rsassa.sig.buffer, signature.signature.rsassa.sig.size
    );
    

    return false;
}