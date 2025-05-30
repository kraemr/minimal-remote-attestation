
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

extern TPM2_RC computeAkName(TPM2B_PUBLIC *pubKey, TPM2B_NAME *nameOut);
extern void makeCred(TPM2B_PUBLIC* akKey, X509* ekCert,TPM2B_ID_OBJECT *cred_blob,TPM2B_ENCRYPTED_SECRET *enc_secret,char* secret);