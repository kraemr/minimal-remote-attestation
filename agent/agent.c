#include "../../ima_verify/inc/ima_template_parser.h"
#include "../../ima_verify/inc/ima_verify.h"
#include "../common/libcbor/src/cbor.h"
#include "../common/quote.h"
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <string.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tpm2_types.h>
#include <unistd.h>

#define BUFFERSIZE 2000
#define MAX_PCRS 30
const uint8_t zeroes[EVP_MAX_MD_SIZE] = {0};

void zeroPcrs(uint8_t pcrs[30][EVP_MAX_MD_SIZE]) {
  for (int32_t i = 0; i < MAX_PCRS; i++) {
    memcpy(pcrs, zeroes, EVP_MAX_MD_SIZE);
  }
}


extern int32_t encodeAttestationCbor( TPM2B_ATTEST attest, uint8_t** serializedOut,size_t* lengthOut);
extern int32_t decodeAttestationCbor(const uint8_t* cborData,uint32_t cborDataLen, TPM2B_ATTEST* attest);

// get dev id from server should obviously happen over a secure channel, as this is a secret
void getDevIdFromServer(){
    
}

// persist devid to identify the device uniquely
void persistDevId(){

}

// never gets persisted in tpm
void getSessionIdServer(){

}




int32_t sendQuote(ESYS_CONTEXT *ectx,ESYS_TR akHandle,int32_t fd){
    // TPM2B_ATTEST is already marshaled
    TPM2B_ATTEST* attest = NULL;
    TPMT_SIGNATURE* sig = NULL;
    TPML_PCR_SELECTION pcrSelection = {
        .count = 1,
        .pcrSelections = {{
            .hash = TPM2_ALG_SHA256,
            .sizeofSelect = 3,
            .pcrSelect = {0x01, 0x00, 0x00}  // PCR 0
        }}
    };

    TPM2B_DATA nonce = {
        .size = 20,
        .buffer = {0x00, 0x01, 0x02, 0x03, 0x04,
                0x05, 0x06, 0x07, 0x08, 0x09,
                0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
                0x0F, 0x10, 0x11, 0x12, 0x13}
    };
    
    TSS2_RC rc = create_quote(ectx,akHandle,&pcrSelection,&nonce,&attest,&sig);
    if(rc != TSS2_RC_SUCCESS){
        return -1;
    }
}




int32_t main(int32_t argc, char* argv[] ) {
    const char* ipAddr = "127.0.0.1";
    const int32_t port = 5000;


    if(argc < 2) {
        printf("Missing path to Ima Log\n");
        return 1;
    }

    if(argc < 3) {
        printf("missing Hash type\n");
        return 1;
    }


    ESYS_CONTEXT *ectx;
    Esys_Initialize(&ectx, NULL, NULL);
    ESYS_TR attestationKeyHandle;
    TPM2B_PUBLIC* publicKey;
    TPM2B_PRIVATE* privateKey;
    // creats and loads the attestation Key, accesible by the attestationkeyhandle
    TSS2_RC rc = createAttestationKey(ectx,&attestationKeyHandle,&publicKey,&privateKey);




    const char* imaPath=argv[1];
    uint16_t hashType = 0;
    int fd = open(imaPath,O_RDONLY);
    uint32_t currentCount = 0;
    uint32_t offset = 0;
    ImaEventSha256 sha256[BUFFERSIZE];
    uint8_t pcrs[30][EVP_MAX_MD_SIZE];
    zeroPcrs(pcrs);

    for(;;) {
    sleep:
        sleep(1);
        //TODO: make this completely hashalgo agnostic
        currentCount = readIMALogSha256(fd,sha256,BUFFERSIZE,CRYPTO_AGILE_SHA256); 
        if(currentCount == 0){
            goto sleep;
        }
        printf("currentCount: %u\n",currentCount);
    }
    Esys_Free(ectx);
    Esys_Free(publicKey);
    Esys_Free(privateKey);
    Esys_Free(sig);  
    return 0;
} 