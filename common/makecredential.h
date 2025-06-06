
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

extern TPM2_RC computeAkName(const TPM2B_PUBLIC *pubKey, TPM2B_NAME *nameOut);
bool kdfa(TPMI_ALG_HASH hashAlg,
          const uint8_t *key, size_t key_len,
          const char *label,
          const uint8_t *contextU, size_t contextU_len,
          const uint8_t *contextV, size_t contextV_len,
          uint8_t *output, size_t bits);