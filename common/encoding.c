#include <cbor.h>
#include <cbor/bytestrings.h>
#include <cbor/common.h>
#include <cbor/data.h>
#include <cbor/ints.h>
#include <cbor/maps.h>
#include <cbor/serialization.h>
#include <cbor/strings.h>
#include <openssl/sha.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_tpm2_types.h>
#include "../common/ima_log_lib/inc/ima_template_parser.h"
#include "../common/ima_log_lib/inc/ima_verify.h"
#include "ima_log_lib/inc/types.h"
#include "libcbor/src/cbor/arrays.h"
extern void displayDigest(uint8_t *pcr, int32_t n);


int32_t encodeAttestationCbor(
    TPM2B_ATTEST attest,
    TPMT_SIGNATURE signature,
    uint8_t** serializedOut,
    size_t* lengthOut
) {
    int32_t ret = 0;
    TSS2_RC rc;
    uint8_t sigBuf[512]; // Enough for typical RSA/ECC signatures
    size_t offset = 0;
    rc = Tss2_MU_TPMT_SIGNATURE_Marshal(&signature, sigBuf, sizeof(sigBuf), &offset);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to marshal TPMT_SIGNATURE: 0x%X\n", rc);
        return -1;
    }
    cbor_item_t* root = cbor_new_definite_map(2);
    _Bool b = cbor_map_add(root, (struct cbor_pair) {
        .key = cbor_move(cbor_build_string("attest")),
        .value = cbor_move(cbor_build_bytestring(attest.attestationData, attest.size))
    });
    b = cbor_map_add(root, (struct cbor_pair) {
        .key = cbor_move(cbor_build_string("signature")),
        .value = cbor_move(cbor_build_bytestring(sigBuf, offset))
    });
    if (!cbor_serialize_alloc(root, serializedOut, lengthOut)) {
        fprintf(stderr, "CBOR serialization failed\n");
        ret = -2;
    }
    cbor_decref(&root);
    return ret;
}

int32_t decodeAttestationCbor(
    const uint8_t* cborData,
    uint32_t cborDataLen,
    TPM2B_ATTEST* attestOut,
    TPMT_SIGNATURE* signatureOut
) {
    struct cbor_load_result result;
    cbor_item_t* root = cbor_load(cborData, cborDataLen, &result);
    if (!root || !cbor_isa_map(root)) {
        fprintf(stderr, "Invalid CBOR format (expected map)\n");
        return -1;
    }

    cbor_item_t *attestItem = NULL, *sigItem = NULL;

    // Loop through CBOR map to find "attest" and "signature"
    for (size_t i = 0; i < cbor_map_size(root); i++) {
        struct cbor_pair pair = cbor_map_handle(root)[i];

        if (cbor_isa_string(pair.key)) {
            char* keyStr = (char*)cbor_string_handle(pair.key);
            size_t keyLen = cbor_string_length(pair.key);

            if (keyLen == 6 && strncmp(keyStr, "attest", 6) == 0) {
                if (!cbor_isa_bytestring(pair.value)) {
                    fprintf(stderr, "'attest' is not a bytestring\n");
                    cbor_decref(&root);
                    return -2;
                }
                attestItem = pair.value;
            } else if (keyLen == 9 && strncmp(keyStr, "signature", 9) == 0) {
                if (!cbor_isa_bytestring(pair.value)) {
                    fprintf(stderr, "'signature' is not a bytestring\n");
                    cbor_decref(&root);
                    return -3;
                }
                sigItem = pair.value;
            }
        }
    }

    if (!attestItem || !sigItem) {
        fprintf(stderr, "Missing 'attest' or 'signature' field in CBOR map\n");
        cbor_decref(&root);
        return -4;
    }

    // Extract attestation data
    size_t attestLen = cbor_bytestring_length(attestItem);
    if (attestLen > sizeof(attestOut->attestationData)) {
        fprintf(stderr, "Attestation data too large\n");
        cbor_decref(&root);
        return -5;
    }

    memcpy(attestOut->attestationData, cbor_bytestring_handle(attestItem), attestLen);
    attestOut->size = attestLen;

    // Unmarshal signature
    size_t offset = 0;
    TSS2_RC rc = Tss2_MU_TPMT_SIGNATURE_Unmarshal(
        cbor_bytestring_handle(sigItem),
        cbor_bytestring_length(sigItem),
        &offset,
        signatureOut
    );

    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to unmarshal TPMT_SIGNATURE: 0x%X\n", rc);
        cbor_decref(&root);
        return -6;
    }

    cbor_decref(&root);
    return 0;
}
int32_t encodePublicKey(TPM2B_PUBLIC* publicKey,uint8_t** serializedOut,size_t* lengthOut) {
    uint8_t buf[1024];
    size_t offset = 0;

    TSS2_RC rc = Tss2_MU_TPM2B_PUBLIC_Marshal(publicKey, buf, sizeof(buf), &offset);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to marshal TPM2B_PUBLIC: 0x%x\n", rc);
        return rc;
    }
    cbor_item_t* item = cbor_build_bytestring(buf,offset);
    cbor_serialize_alloc(item,serializedOut,lengthOut);
    cbor_decref(&item);
    return rc;   
}

int32_t decodePublicKey(const uint8_t* cborData, uint32_t cborDataLen, TPM2B_PUBLIC* publicKeyOut) {
    struct cbor_load_result result;
    cbor_item_t* t = cbor_load(cborData, cborDataLen, &result);
    if (!t || !cbor_isa_bytestring(t)) {
        fprintf(stderr, "Expected top-level CBOR bytestring for TPM2B_PUBLIC\n");
        if (t) cbor_decref(&t);
        return -1;
    }

    const uint8_t* buf = cbor_bytestring_handle(t);
    size_t bufLen = cbor_bytestring_length(t);
    size_t offset = 0;

    TSS2_RC rc = Tss2_MU_TPM2B_PUBLIC_Unmarshal(buf, bufLen, &offset, publicKeyOut);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Unmarshal failed: 0x%X\n", rc);
    }

    cbor_decref(&t);
    return rc;
}


ImaEventSha256 decodeImaEvent(cbor_item_t* item){
    ImaEventSha256 event;
    size_t allocatedSize = cbor_array_size(item);
    if(allocatedSize < 6){
        printf("elements missing\n");
    }
    cbor_item_t* pcr = cbor_array_get(item,0);
    cbor_item_t* templateDataLength = cbor_array_get(item,1);
    cbor_item_t* templateNameLength = cbor_array_get(item,2);    
    cbor_item_t* templateName = cbor_array_get(item,3);
    cbor_item_t* hashOfTemplate = cbor_array_get(item,4);
    cbor_item_t* templateData = cbor_array_get(item,5);

    event.pcrIndex = cbor_get_uint32(pcr);
    event.templateDataLength = cbor_get_uint32(templateDataLength);
    event.templateNameLength = cbor_get_uint32(templateNameLength);
    event.templateData = malloc(event.templateDataLength);    
    
    memcpy(event.hashOfTemplate,hashOfTemplate->data,SHA256_DIGEST_LENGTH);
    memcpy(event.templateData,templateData->data,event.templateDataLength);
    memcpy(event.templateName, templateName->data,event.templateNameLength );
    
    return event;
}


int32_t decodeImaEvents(const uint8_t* cborData,uint32_t cborDataLen, ImaEventSha256** events, size_t* size ) {
    struct cbor_load_result result;
    cbor_item_t* arrayImaEvents = cbor_load(cborData,cborDataLen, &result);
    size_t allocatedSize = cbor_array_size(arrayImaEvents);
    uint32_t res=0;
    size_t imaEventAllocatedSize = sizeof(ImaEventSha256) * allocatedSize;
    
    (*size) = allocatedSize;
    (*events) = (ImaEventSha256*)malloc(imaEventAllocatedSize);
    // This needs to be after the alloc, since we get a new memory address after malloc
    ImaEventSha256* eventsRef = (*events);
    for (size_t i = 0; i < allocatedSize; i++){
        cbor_item_t* arrayItem;
        arrayItem=cbor_array_get(arrayImaEvents, i);
        ImaEventSha256 ev =  decodeImaEvent(arrayItem);
        eventsRef[i] = ev;
    }

    return 0;
}


cbor_item_t* encodeImaEvent(struct ImaEventSha256* event) {
    cbor_item_t *array = cbor_new_definite_array(6);
    uint32_t result = 0;
    result = cbor_array_push(array, cbor_build_uint32(event->pcrIndex));
    result = cbor_array_push(array, cbor_build_uint32(event->templateDataLength));    
    result = cbor_array_push(array, cbor_build_uint32(event->templateNameLength));
    result = cbor_array_push(array, cbor_build_bytestring((uint8_t*)event->templateName,event->templateNameLength));
    result = cbor_array_push(array, cbor_build_bytestring(event->hashOfTemplate,SHA256_DIGEST_LENGTH));
    result = cbor_array_push(array, cbor_build_bytestring(event->templateData,event->templateDataLength));
    ImaEventSha256 s = decodeImaEvent(array);
    //displayDigest(s.templateData, 32 );
    //printf("\n");

    return array;
}

int32_t encodeImaEvents(struct ImaEventSha256* events, uint32_t len,uint8_t** serializedOut,size_t* lengthOut ) {
    cbor_item_t *array = cbor_new_definite_array(len);
    for(uint32_t i = 0; i < len; i++) {
        ImaEventSha256* sha256 = &events[i];
        cbor_item_t* res = encodeImaEvent(sha256);
        if( !cbor_array_push(array, res) ) {
            printf("cbor_array_push failed encodeImaEvents");
        }
    }
    cbor_serialize_alloc(array,serializedOut,lengthOut);
    cbor_decref(&array);
    return 0;
}

