#include "../common/ima_log_lib/inc/ima_template_parser.h"
#include "../common/ima_log_lib/inc/ima_verify.h"
#include "../common/libcbor/src/cbor.h"
#include "../common/quote.h"
#include "../common/request.h"
#include "../common/encoding.h"
#include "../common/makecredential.h"
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tss2/tss2_common.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_sys.h>
#include <tss2/tss2_tpm2_types.h>
#include <unistd.h>

#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>

#define BUFFERSIZE 500
#define EK_CERT_NV_INDEX 0x01C00002  // RSA EK cert NV index
#define EK_HANDLE 0x81010001

void getSessionIdServer() {}
extern void displayDigest(uint8_t* pcr, uint32_t len);
char response[4096]={0};


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

void makeCred(TPM2B_PUBLIC* akKey, X509* ekCert,TPM2B_ID_OBJECT *cred_blob, TPM2B_ENCRYPTED_SECRET *enc_secret){      
  TPM2B_NAME name = {0};    
  EVP_PKEY *ek_pubkey = NULL;
  RSA *rsa = NULL;
  EVP_MD_CTX *mdctx = NULL;

  uint8_t buf[2048] = {0};
  size_t len = 0;
  // 2. compute ak Name
  computeAkName(akKey,&name);   
  TSS2_RC rc  =  Tss2_MU_TPM2B_NAME_Marshal(&name,buf,2048,&len);
  
  if(rc != TSS2_RC_SUCCESS){
    printf("Tss2_MU_TPM2B_NAME_MARSHAL failed \n");
    return;
  }

  char* akHex = bytes_to_hex_lowercase(name.name,name.size);
  char cmd_filled[2048];

  
  system("openssl x509 -in /tmp/ek_rsa.pem -pubkey -noout > /tmp/ek_pub.pem");
sprintf(cmd_filled,
    "echo \"12345678\" | (tpm2 makecredential -Q -u /tmp/ek_pub.pem -s - -n %s -o mkcred.out -G rsa) > encrypted_secret.bin",
    akHex);  system(cmd_filled);

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


  printf("%d %d\n",enc_secret->size,cred_blob->size);
  
  fclose(fp);  

}

int32_t getEKCertificate(uint8_t certificate[4096] , size_t* bytesRead) {
  system("tpm2_nvread 0x01c00002 > /tmp/ek_rsa.der");
  system("openssl x509 -inform DER -in /tmp/ek_rsa.der -out /tmp/ek_rsa.pem");
  int fd = open("/tmp/ek_rsa.pem",O_RDONLY);
  if(fd == -1){
    printf("couldnt opne ek_rsa.pem\n");
  }  
  (*bytesRead) = read(fd,certificate,4096);
  printf("%s",certificate);
  close(fd);
  return 0;
}

int32_t sendQuote(ESYS_CONTEXT *ectx, ESYS_TR akHandle) {
  const char *url = "http://127.0.0.1:8084/quote";
  // TPM2B_ATTEST is already marshaled
  TPM2B_ATTEST *attest = NULL;
  TPMT_SIGNATURE *sig = NULL;

  // For ima we select PCR 10
  TPML_PCR_SELECTION pcrSelection = {
    .count = 1,
    .pcrSelections = {{
        .hash = TPM2_ALG_SHA256,
        .sizeofSelect = 3,
        .pcrSelect = {0x00, 0x04, 0x00} // PCR 10 = bit 2 in byte 1
    }}
  };

  TPM2B_DATA nonce = {.size = 20,
                      .buffer = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                                 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
                                 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13}};

  TSS2_RC rc = create_quote(ectx, akHandle, &pcrSelection, &nonce, &attest, &sig);

    
  if (rc != TSS2_RC_SUCCESS) {
    return -1;
  }

  uint8_t* buf = NULL;
  size_t len = 0;
  
  encodeAttestationCbor(*attest,*sig,&buf,&len);
  sendPostCbor(url, buf, len, response);
  
  free(buf);
  // after sending Free we dont need it anymore
  Esys_Free(sig);
  Esys_Free(attest);
  return 0;
}



TSS2_RC activateCredential(ESYS_CONTEXT* ctx,ESYS_TR akHandle, ESYS_TR ekHandle,TPM2B_ID_OBJECT* credentialBlob,TPM2B_ENCRYPTED_SECRET* secret) {
    ESYS_TR session = ESYS_TR_NONE;

    TPM2B_NONCE nonceCaller = {
        .size = 20,
        .buffer = {0}  // Usually random or 0s
    };

    TPMT_SYM_DEF symmetric = {
        .algorithm = TPM2_ALG_NULL,
    };

    TSS2_RC rc = Esys_StartAuthSession(
        ctx,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,       // session1
        ESYS_TR_NONE,       // session2
        ESYS_TR_NONE,       // session3
        &nonceCaller,
        TPM2_SE_POLICY,
        &symmetric,
        TPM2_ALG_SHA256,
        &session
    );
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Esys_StartAuthSession failed: 0x%x\n", rc);
        return 1;
    }

    // Apply PolicySecret using Endorsement hierarchy
    TPM2B_NONCE nonceTpm = { .size = 0 };
    TPM2B_DIGEST cpHashA = { .size = 0 };
    TPM2B_NONCE policyRef = { .size = 0 };
    INT32 expiration = 0;
    TPM2B_TIMEOUT *timeout = NULL;
    TPMT_TK_AUTH *policyTicket = NULL;

    rc = Esys_PolicySecret(
        ctx,
        ESYS_TR_RH_ENDORSEMENT,
        session,
        ESYS_TR_PASSWORD, 
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &nonceTpm,
        &cpHashA,
        &policyRef,
        expiration,
        &timeout,
        &policyTicket
    );
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Esys_PolicySecret failed: 0x%x\n", rc);
        return 1;
    }

    TPM2B_AUTH ekAuth = { .size = 0 }; // assuming EK has empty auth
    rc = Esys_TR_SetAuth(ctx, ekHandle, &ekAuth);

    TPM2B_DIGEST *certified;
    rc = Esys_ActivateCredential(ctx,
                                 akHandle, ekHandle,
                                 ESYS_TR_PASSWORD, session, ESYS_TR_NONE,
                                 credentialBlob, secret, &certified);

    printf("Credential activated. Secret: ");
    for (int i = 0; i < certified->size; i++)
        printf("%02x", certified->buffer[i]);
    printf("\n");

    return rc;
}

int32_t enroll(ESYS_CONTEXT* ectx, ESYS_TR* attestationKeyHandle, TPM2B_PUBLIC** publicKey){
  const char *url = "http://127.0.0.1:8084/enroll";
  size_t ekCertLen=0;
  uint8_t buf[4096];
  uint8_t* serializedCborPubKey = NULL;
  size_t len = 0;
  TSS2_RC rc = 0;
  
  TPM2B_DATA qualifyingData = { .size = 0 };
  TPMT_SIG_SCHEME inScheme = {
      .scheme = TPM2_ALG_NULL, 
  };
  TPM2B_ATTEST* attest;
  TPMT_SIGNATURE* signature;
  
  getEKCertificate(buf,&ekCertLen);

  ESYS_TR ekHandle;
  rc = Esys_TR_FromTPMPublic(ectx, EK_HANDLE, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &ekHandle);
  rc = createAttestationKey(ectx,attestationKeyHandle,publicKey);  
  rc = Esys_Certify(ectx, *attestationKeyHandle, *attestationKeyHandle, ESYS_TR_PASSWORD, ESYS_TR_PASSWORD,ESYS_TR_NONE, &qualifyingData, &inScheme, &attest, &signature);
  
  BIO* bio = BIO_new_mem_buf(buf, ekCertLen);
  if (!bio) return 0;
  X509* cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
  BIO_free(bio);  
   
  TPM2B_NAME *akName;
  rc = Esys_TR_GetName(ectx, *attestationKeyHandle, &akName);
  TPM2B_DIGEST secret_data = {
      .size = 20,
  };
  RAND_bytes(secret_data.buffer, secret_data.size);

  TPM2B_ID_OBJECT credentialBlob = {0};
  TPM2B_ENCRYPTED_SECRET secret = {0};


  // rc = Esys_MakeCredential(ectx, ekHandle,
  //                           ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
  //                           &secret_data, akName, &credentialBlob, &secret);  
  
  makeCred(*publicKey,NULL,&credentialBlob,&secret);



  rc = activateCredential(ectx,*attestationKeyHandle, ekHandle , &credentialBlob, &secret);
  if(rc != TSS2_RC_SUCCESS){
    printf("activateCredential failed for attestation Key %d \n",rc);
  }
  encodePublicKey(*publicKey,attest,signature,buf,ekCertLen,&serializedCborPubKey,&len);
  sendPostCbor(url, serializedCborPubKey, len, response);
  free(serializedCborPubKey);
  return rc;
}

int32_t main(int32_t argc, char *argv[]) {
  const char *imaUrl = "http://127.0.0.1:8084/ima";
  const char *imaPath = "/sys/kernel/security/ima/binary_runtime_measurements_sha256";
  // For testing this is reduced to 60 seconds
  const uint32_t QUOTE_TIME = 60;

  uint32_t measurementsCount = 0;  
  uint32_t offset = 0;
  ImaEventSha256 measurements[BUFFERSIZE]={0};  
  uint8_t* serialOut = NULL;
  size_t size = 0;
  size_t len = 0;
  uint16_t hashType = 0;  
  ESYS_CONTEXT *ectx;
  TPM2B_PUBLIC *publicKey;
  ESYS_TR attestationKeyHandle;
  int32_t fd = -1;
  Esys_Initialize(&ectx, NULL, NULL);
  initCurl();    
  enroll(ectx,&attestationKeyHandle,&publicKey);
  
  
  
  return 0;
  
  fd = open(imaPath, O_RDONLY);  
  if (fd == -1) {
    printf("failed to open IMA Event Log at: %s.\n \
        Please check that your user has correct permissions and that the file exists\n",
           imaPath);
    return 1;
  }  

  time_t lastTs = time(NULL);
  
  for (;;) {
    sleep:    
    if( (time(NULL) - lastTs) > QUOTE_TIME ) {
      printf("sendquote time diff %ld\n", (time(NULL) - lastTs));
      sendQuote(ectx, attestationKeyHandle);
      lastTs = time(NULL);
    }        
    memset(measurements,0,sizeof(ImaEventSha256) * BUFFERSIZE );
    measurementsCount = readImaLog(fd,CRYPTO_AGILE_SHA256,measurements, BUFFERSIZE);
    if (measurementsCount == 0) {
      goto sleep;
    }         
    printf("mcount %d\n",measurementsCount);
    int32_t res = encodeImaEvents(measurements,measurementsCount, &serialOut,&size);
    sendPostCbor(imaUrl, serialOut, size, response);  
    free(serialOut);
  }
 
  Esys_Free(ectx);
  Esys_Free(publicKey);
  return 0;
}
