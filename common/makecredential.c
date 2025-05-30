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

char *bytes_to_hex_lowercase(const uint8_t *data, size_t len) {
    if (!data || len == 0)
        return NULL;

    // Each byte becomes two hex characters + 1 for null terminator
    char *hexstr = malloc(len * 2 + 1);
    if (!hexstr)
        return NULL;

    for (size_t i = 0; i < len; i++) {
        sprintf(hexstr + i * 2, "%02x", data[i]);
    }

    hexstr[len * 2] = '\0'; // null terminator
    return hexstr;
}

TPM2_RC computeAkName(TPM2B_PUBLIC *pubkey, TPM2B_NAME *name_out) {
    if (pubkey == NULL || name_out == NULL) return TSS2_ESYS_RC_BAD_REFERENCE;

    // 1. Marshal TPMT_PUBLIC
    uint8_t buffer[1024];
    size_t offset = 0;
    TSS2_RC rc = Tss2_MU_TPMT_PUBLIC_Marshal(&pubkey->publicArea, buffer, sizeof(buffer), &offset);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Error marshaling TPMT_PUBLIC: 0x%x\n", rc);
        return rc;
    }

    // 2. Determine hash algorithm
    TPMI_ALG_HASH nameAlg = pubkey->publicArea.nameAlg;
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

char *base64_encode(const unsigned char *input, int len,char* out, int *out_len)
{
    BIO *bmem = BIO_new(BIO_s_mem());
    BIO *b64 = BIO_new(BIO_f_base64());

    b64 = BIO_push(b64, bmem);

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, input, len);
    BIO_flush(b64);

    BUF_MEM *bptr;
    BIO_get_mem_ptr(b64, &bptr);

    memcpy(out, bptr->data, bptr->length);
    out[bptr->length] = 0;

    if (out_len) *out_len = bptr->length;

    BIO_free_all(b64);
    return out;
}


#include <stdio.h>
#include <stdlib.h>

void generate_random_string(char *out, size_t n) {
    const char charset[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";

    FILE *fp = fopen("/dev/urandom", "r");
    if (!fp) return;

    for (size_t i = 0; i < n; i++) {
        unsigned char rand_byte;
        fread(&rand_byte, 1, 1, fp);
        out[i] = charset[rand_byte % (sizeof(charset) - 1)];
    }

    fclose(fp);
    out[n] = '\0';
}


void makeCred(TPM2B_PUBLIC* akKey, X509* ekCert,TPM2B_ID_OBJECT *cred_blob,TPM2B_ENCRYPTED_SECRET *enc_secret,char* secret){      
  TPM2B_NAME name = {0};    
  EVP_PKEY *ek_pubkey = NULL;
  RSA *rsa = NULL;
  EVP_MD_CTX *mdctx = NULL;
  uint8_t buf[2048] = {0};
  size_t len = 0;

  computeAkName(akKey,&name);   
  TSS2_RC rc  =  Tss2_MU_TPM2B_NAME_Marshal(&name,buf,2048,&len);
  
  if(rc != TSS2_RC_SUCCESS){
    printf("Tss2_MU_TPM2B_NAME_MARSHAL failed \n");
    return;
  }

  char* akHex = bytes_to_hex_lowercase(name.name,name.size);
  char cmd_filled[2048];  
  system("openssl x509 -in /tmp/ek_rsa.pem -pubkey -noout > /tmp/ek_pub.pem");
  
  generate_random_string(secret,24);
  sprintf(cmd_filled,
    "echo \"%s\" | (tpm2 makecredential -Q -u /tmp/ek_pub.pem -s - -n %s -o mkcred.out -G rsa) > encrypted_secret.bin",
    secret,akHex);  
  printf("%s\n",cmd_filled );
  system(cmd_filled);

  FILE * fp = fopen("mkcred.out","rb");  
  fseek(fp, 8,SEEK_SET);  

  
  fread(&cred_blob->size,2,1,fp);
  uint8_t little_endian[2] = {0};
  little_endian[0] = (cred_blob->size >> 8) & 0xFF;         // LSB first
  little_endian[1] = (cred_blob->size) & 0xFF;  // MSB second
  cred_blob->size = (uint16_t)little_endian[0] | ((uint16_t)little_endian[1] << 8);
  memcpy(&cred_blob->size, little_endian, sizeof(cred_blob->size));
  fread(cred_blob->credential,cred_blob->size,1,fp);  

  fread(&enc_secret->size,2,1,fp);
  little_endian[0] = (enc_secret->size >> 8) & 0xFF;         // LSB first
  little_endian[1] = (enc_secret->size) & 0xFF;  // MSB second
  enc_secret->size = (uint16_t)little_endian[0] | ((uint16_t)little_endian[1] << 8);
  memcpy(&enc_secret->size, little_endian, sizeof(enc_secret->size));
  fread(enc_secret->secret,enc_secret->size,1,fp);


  printf("cred %d %d\n",cred_blob->size,enc_secret->size);
  
  fclose(fp);  

}
