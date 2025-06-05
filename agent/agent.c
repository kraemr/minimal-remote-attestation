#include "../common/ima_log_lib/inc/ima_template_parser.h"
#include "../common/ima_log_lib/inc/ima_verify.h"
#include "../common/libcbor/src/cbor.h"
#include "../common/quote.h"
#include "../common/request.h"
#include "../common/encoding.h"
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <tss2/tss2_common.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tpm2_types.h>
#include <unistd.h>

#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>

#define BUFFERSIZE 500
#define EK_CERT_NV_INDEX 0x01C00002  // RSA EK cert NV index

extern TSS2_RC readDevId(ESYS_CONTEXT* esys_ctx,uint8_t buf[64]);
extern TSS2_RC writeDevId(ESYS_CONTEXT* esys_ctx,const uint8_t* data, uint32_t size);
void getSessionIdServer() {}
extern void displayDigest(uint8_t* pcr, uint32_t len);
char response[4096]={0};

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

  rc = createAttestationKey(ectx,attestationKeyHandle,publicKey);  
  rc = Esys_Certify(ectx, *attestationKeyHandle, *attestationKeyHandle, ESYS_TR_PASSWORD, ESYS_TR_PASSWORD,ESYS_TR_NONE, &qualifyingData, &inScheme, &attest, &signature);
  
  BIO* bio = BIO_new_mem_buf(buf, ekCertLen);
  if (!bio) return 0;
  X509* cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
  BIO_free(bio);  

  if(rc != TSS2_RC_SUCCESS){
    printf("Esys_Certify failed for attestation Key %d \n",rc);
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
  const uint32_t FIVEMINUTES = 60;

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
  enroll(ectx,&attestationKeyHandle,&publicKey);
  fd = open(imaPath, O_RDONLY);  
  if (fd == -1) {
    printf("failed to open IMA Event Log at: %s.\n \
        Please check that your user has correct permissions and that the file exists\n",
           imaPath);
    return 1;
  }  
  initCurl();    
  time_t lastTs = time(NULL);
  int i = 0;
  for (;;) {
    sleep:

    
    if( (time(NULL) - lastTs) > FIVEMINUTES ) {
      printf("sendquote time diff %d\n", (time(NULL) - lastTs));
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
