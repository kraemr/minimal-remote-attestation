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
#include <string.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tpm2_types.h>
#include <unistd.h>
#define BUFFERSIZE 500
extern TSS2_RC readDevId(ESYS_CONTEXT* esys_ctx,uint8_t buf[64]);
extern TSS2_RC writeDevId(ESYS_CONTEXT* esys_ctx,const uint8_t* data, uint32_t size);
void getSessionIdServer() {}
extern void displayDigest(uint8_t* pcr, uint32_t len);
char response[4096]={0};

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

// called after /enroll is request on this agent
void createKeys() {
  //TSS2_RC rc = createAttestationKey(ectx, &attestationKeyHandle, &publicKey,&privateKey);
}

int32_t main(int32_t argc, char *argv[]) {
  const char *url = "http://127.0.0.1:8084/enroll";
  const char *imaUrl = "http://127.0.0.1:8084/ima";
  uint32_t currentCount = 0;
  uint64_t accCount = 0;
  uint32_t offset = 0;
  ImaEventSha256 sha256[BUFFERSIZE]={0};  
  uint8_t* serialOut = NULL;
  size_t size = 0;
  ESYS_CONTEXT *ectx;
  ESYS_TR attestationKeyHandle;
  TPM2B_PUBLIC *publicKey;
  uint8_t* serializedCborPubKey = NULL;
  size_t len = 0;
  const char *imaPath = argv[1];
  uint16_t hashType = 0;
  int fd = -1;

  if (argc < 3) {
    printf("Missing Args usage: ./agent pathToIMALogSha256 sha256\n");
    return 1;
  }
  fd = open(imaPath, O_RDONLY);
  if (fd == -1) {
    printf("failed to open IMA Event Log at: %s.\n \
        Please check that your user has correct permissions and that the file exists\n",
           imaPath);
    return 1;
  }
  
  Esys_Initialize(&ectx, NULL, NULL);
  TSS2_RC rc = getSigningKey(ectx,&attestationKeyHandle,&publicKey);
  initCurl();  
  encodePublicKey(publicKey,&serializedCborPubKey,&len);
  sendPostCbor(url, serializedCborPubKey, len, response);

  for (;;) {
    sleep:
    sleep(1);
    // TODO: make this completely hashalgo agnostic
    memset(sha256,0,sizeof(ImaEventSha256) * BUFFERSIZE );
    currentCount = readImaLog(fd,CRYPTO_AGILE_SHA256,sha256, BUFFERSIZE);
    if (currentCount == 0) {
      goto sleep;
    }
    accCount += currentCount;    
    int32_t res = encodeImaEvents(sha256,currentCount, &serialOut,&size);
    sendPostCbor(imaUrl, serialOut, size, response);
    if(accCount > 1000 ){
      sendQuote(ectx, attestationKeyHandle);
      accCount = 0;
    }
    free(serialOut);
  }
 
  Esys_Free(ectx);
  Esys_Free(publicKey);
  return 0;
}