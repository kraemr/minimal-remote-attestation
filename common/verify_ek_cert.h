#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include <stdio.h>

extern X509* loadPemX509FromMemory(const uint8_t* pem_buf, size_t len);
int32_t extractPublicKey(X509 *ek_cert, EVP_PKEY* key);
int32_t verifyEkCertificate(const char *root_bundle_path, uint8_t* ekCertificate, size_t ekCertLen );