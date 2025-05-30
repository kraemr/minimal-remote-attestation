#include "../common/ima_log_lib/inc/ima_template_parser.h"
#include "../common/ima_log_lib/inc/ima_verify.h"
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
#include "../common/verify_ek_cert.h"

#define BUFFERSIZE 500
#define EK_CERT_NV_INDEX 0x01C00002  // RSA EK cert NV index
#define EK_HANDLE 0x81010001

void getSessionIdServer() {}
extern void displayDigest(uint8_t* pcr, uint32_t len);
char response[4096]={0};
#define IDENTITY_LABEL "IDENTITY"

typedef struct AttesterContext {
    ESYS_TR akHandle;
    ESYS_TR ekHandle;
    TPM2B_PUBLIC* publicKey;
    ESYS_CONTEXT* ctx;
    ImaEventSha256 measurements[BUFFERSIZE];
    size_t measurements_count;    
    size_t ekCertificateLen;
    char session_id[65];
    uint8_t ekCertificateBuffer[4096]; // should be more than enough
    const char* base_url;
}AttesterContext;

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

int32_t sendQuote(AttesterContext* ctx, ESYS_TR akHandle) {
  const char *url = "http://127.0.0.1:8084/attestation";
  TPM2B_ATTEST *attest = NULL;
  TPMT_SIGNATURE *sig = NULL;
  TPML_PCR_SELECTION pcrSelection = {
    .count = 1,
    .pcrSelections = {{
        .hash = TPM2_ALG_SHA256,
        .sizeofSelect = 3,
        .pcrSelect = {0x00, 0x04, 0x00} // PCR 10 = bit 2 in byte 1
    }}
  };

  // we dont use a nonce for replay protection, just here because its required
  TPM2B_DATA nonce = {.size = 20,
                      .buffer = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                                 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
                                 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13}};
  TSS2_RC rc = create_quote(ctx->ctx, akHandle, &pcrSelection, &nonce, &attest, &sig);
  if (rc != TSS2_RC_SUCCESS) {
    return -1;
  }
  uint8_t* buf = NULL;
  size_t len = 0;
  encodeAttestationCbor(*attest,*sig,&buf,&len);
  size_t size = 0;
  sendPostCbor(url, buf, len, response,ctx->session_id,&size);
  free(buf);  
  Esys_Free(sig);
  Esys_Free(attest);
  return 0;
}


TPM2_RC createEKAKCertification(AttesterContext* state,TPM2B_ATTEST* attest, TPMT_SIGNATURE* signature) {
    TPM2B_DATA qualifyingData = { .size = 0 };
    TPMT_SIG_SCHEME inScheme = {
        .scheme = TPM2_ALG_NULL, 
    };
    TPM2_RC rc = Esys_Certify(
        state->ctx,
        state->akHandle, 
        state->akHandle, 
        ESYS_TR_PASSWORD, 
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE, 
        &qualifyingData, 
        &inScheme, 
        &attest, 
        &signature
    );
    return rc;
}

TSS2_RC activateCredential(
    ESYS_CONTEXT* ctx,
    ESYS_TR akHandle, 
    ESYS_TR ekHandle,
    TPM2B_ID_OBJECT* credentialBlob,
    TPM2B_ENCRYPTED_SECRET* secret,
    TPM2B_DIGEST ** certified){
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
    rc = Esys_ActivateCredential(ctx,
                                 akHandle, ekHandle,
                                 ESYS_TR_PASSWORD, session, ESYS_TR_NONE,
                                 credentialBlob, secret, certified);

    printf("Credential activated. Secret: ");
    for (int i = 0; i < (*certified)->size; i++)
        printf("%02x", (*certified)->buffer[i]);
    printf("\n");

    return rc;}


#include "../common/makecredential.h"
int32_t enroll_challenge(AttesterContext* state,TPM2B_DIGEST** decrypted_secret){
    const char *url = "http://127.0.0.1:8084/enroll-challenge";
    uint8_t* serializedCborPubKey = NULL;
    size_t len = 0;
    size_t response_len = 0;
    TSS2_RC rc = 0;  
    TPM2B_DATA qualifyingData = { .size = 0 };
    TPMT_SIG_SCHEME inScheme = {
        .scheme = TPM2_ALG_NULL, 
    };
    TPM2B_ATTEST* attest;
    TPMT_SIGNATURE* signature;    
    int res = createEKAKCertification(state,attest,signature);
    rc = Esys_Certify(state->ctx, state->akHandle, state->akHandle, ESYS_TR_PASSWORD, ESYS_TR_PASSWORD,ESYS_TR_NONE, &qualifyingData, &inScheme, &attest, &signature);    
    encodePublicKey(state->publicKey,attest,signature,state->ekCertificateBuffer,state->ekCertificateLen,&serializedCborPubKey,&len);
    sendPostCbor(url, serializedCborPubKey, len, response, state->session_id,&response_len);    
    free(serializedCborPubKey);
    
    TPM2B_ID_OBJECT credentialBlob;
    TPM2B_ENCRYPTED_SECRET secret;

    unsigned int session_id_len = 0;
    decode_cred_from_cbor((unsigned char*)response, response_len,&credentialBlob, &secret,(unsigned char*)state->session_id,&session_id_len);    
    state->session_id[64] = '\0';
    printf("SESSION %s\n",state->session_id);
    rc = activateCredential(state->ctx,state->akHandle, state->ekHandle, &credentialBlob,&secret,decrypted_secret);
    if(rc != TSS2_RC_SUCCESS){
        printf("activateCredential failed for attestation Key %d \n",rc);
        exit(0);
    }    
    return rc;
}

int32_t try_enroll(
    AttesterContext* ctx,
    TPM2B_DIGEST* decrypted_secret
) {
    const char *enroll_url = "http://127.0.0.1:8084/enroll";
    char temp[256]={0};
    memcpy(temp, decrypted_secret->buffer, decrypted_secret->size);
    char buf[65]={0};
    memcpy(buf, decrypted_secret->buffer, decrypted_secret->size);
    buf[64] = '\0';
    return sendStringWithSession(enroll_url,buf, ctx->session_id);
}


int initializeAttesterState(AttesterContext* state) {
    Esys_Initialize(&state->ctx, NULL, NULL);
    TPM2_RC rc = Esys_TR_FromTPMPublic(state->ctx, EK_HANDLE, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &state->ekHandle);
    rc = createAttestationKey(state->ctx,&state->akHandle,&state->publicKey);  
    getEKCertificate(state->ekCertificateBuffer,&state->ekCertificateLen);
    return 0;
}

void attestLoop(AttesterContext* ctx, const char* path, uint32_t quote_time){
    int fd = open(path, O_RDONLY);  
    if (fd == -1) {
        printf("failed to open IMA Event Log at: %s.\n \
            Please check that your user has correct permissions and that the file exists\n",
            path);
    }  

    time_t lastTs = time(NULL);
    uint8_t* serialized_out = NULL;
    size_t serialized_out_len = 0;

    for (;;) {
        sleep:    
        if( (time(NULL) - lastTs) > quote_time ) {            
            sendQuote(ctx,ctx->akHandle);
            lastTs = time(NULL);
        }        
        memset(ctx->measurements,0,sizeof(ImaEventSha256) * BUFFERSIZE );
        ctx->measurements_count = readImaLog(fd,CRYPTO_AGILE_SHA256,ctx->measurements, BUFFERSIZE);
        if (ctx->measurements_count == 0) {
            goto sleep;
        }         
        size_t len = 0;
        int32_t res = encodeImaEvents(ctx->measurements, ctx->measurements_count, &serialized_out,&serialized_out_len);
        sendPostCbor("http://127.0.0.1:8084/measurements", serialized_out, serialized_out_len, response,ctx->session_id,&len);  
        free(serialized_out);
    }
}

int main(){
    AttesterContext ctx;
    ctx.base_url = "http://127.0.0.1:8084/";    
    const char *imaPath = "/sys/kernel/security/ima/binary_runtime_measurements_sha256";
    const uint32_t QUOTE_TIME = 60;
    TPM2B_DIGEST* secret;    
    TPM2B_ATTEST* attest;
    TPMT_SIGNATURE* signature;
    int res = 0;
    res = initializeAttesterState(&ctx);   
    enroll_challenge(&ctx,&secret);
    int32_t enrollment_success = try_enroll(&ctx,secret);
    if(enrollment_success){
        attestLoop(&ctx,imaPath,QUOTE_TIME);
    }else{
        exit(0);
    }
}   



/*int32_t main(int32_t argc, char *argv[]) {
  const char *imaUrl = "http://127.0.0.1:8084/measurements";
  const char *imaPath = "/sys/kernel/security/ima/binary_runtime_measurements_sha256";
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
  char enroll_secret[128] = {0};
  size_t enroll_secret_len = 0;
  Esys_Initialize(&ectx, NULL, NULL);
  initCurl();
  char session_id[64];
  TPM2B_DIGEST* decrypted_secret;
  
  enroll_challenge(ectx,&attestationKeyHandle,&publicKey,&decrypted_secret,session_id);
  

  if( try_enroll(decrypted_secret,session_id) != 0 ) {
    printf("Failed to Enroll!! Exiting");
    exit(1);
  }


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
    size_t len = 0;
    sendPostCbor(imaUrl, serialOut, size, response,&len);  
    free(serialOut);
  }
 
  Esys_Free(ectx);
  Esys_Free(publicKey);
  return 0;
}
*/
