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
#include "libcbor/src/cbor/arrays.h"


extern void displayDigest(uint8_t *pcr, int32_t n);
int32_t encodeAttestationCbor( TPM2B_ATTEST attest, uint8_t** serializedOut,size_t* lengthOut) {
    cbor_item_t* item = cbor_build_bytestring(attest.attestationData,attest.size);
    cbor_serialize_alloc(item,serializedOut,lengthOut);
    cbor_decref(&item);
    return 0;
}

// returns the marshaled version of the attestation
int32_t decodeAttestationCbor(const uint8_t* cborData,uint32_t cborDataLen, TPM2B_ATTEST* attestOut) {
    struct cbor_load_result result;
    cbor_item_t* t = cbor_load(cborData,cborDataLen, &result);
    memcpy(attestOut->attestationData,t->data,t->metadata.bytestring_metadata.length);
    attestOut->size = t->metadata.bytestring_metadata.length;
    cbor_decref(&t);
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

int32_t decodePublicKey(const uint8_t* cborData,uint32_t cborDataLen, TPM2B_PUBLIC* publicKeyOut){
    struct cbor_load_result result;
    cbor_item_t* t = cbor_load(cborData,cborDataLen, &result);
    size_t offset=0;
    TSS2_RC rc = Tss2_MU_TPM2B_PUBLIC_Unmarshal(t->data, t->metadata.bytestring_metadata.length,&offset,publicKeyOut);
    cbor_decref(&t);
    return 0;
}

cbor_item_t* encodeImaEvent(struct ImaEventSha256* event) {
    cbor_item_t *array = cbor_new_definite_array(7);
    uint32_t result = 0;
    result = cbor_array_push(array, cbor_build_uint32(event->pcrIndex));
    result = cbor_array_push(array, cbor_build_uint32(event->templateDataLength));    
    result = cbor_array_push(array, cbor_build_uint32(event->templateNameLength));
    result = cbor_array_push(array, cbor_build_uint32(event->templateType));
    result = cbor_array_push(array, cbor_build_bytestring(event->templateName,event->templateNameLength));
    result = cbor_array_push(array, cbor_build_bytestring(event->hashOfTemplate,SHA256_DIGEST_LENGTH));
    result = cbor_array_push(array, cbor_build_bytestring(event->templateData,event->templateDataLength));
    //result = cbor_array_push(array, cbor_build_bytestring(event->parsedTemplateData,event->templateNameLength));    
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

ImaEventSha256 decodeImaEvent(cbor_item_t* item){
    ImaEventSha256 event;
    size_t allocatedSize = cbor_array_size(item);
    if(allocatedSize < 7){
        printf("elements missing\n");
    }
    cbor_item_t* pcr = cbor_array_get(item,0);
    cbor_item_t* templateDataLength = cbor_array_get(item,1);
    cbor_item_t* templateNameLength = cbor_array_get(item,2);
    cbor_item_t* templateType = cbor_array_get(item,3);
    
    cbor_item_t* templateName = cbor_array_get(item,4);
    cbor_item_t* hashOfTemplate = cbor_array_get(item,5);
    cbor_item_t* templateData = cbor_array_get(item,6);

    event.pcrIndex = cbor_get_uint32(pcr);
    event.templateDataLength = cbor_get_uint32(templateDataLength);
    event.templateNameLength = cbor_get_uint32(templateNameLength);
    event.templateType = cbor_get_uint32(templateType);

    event.templateData = malloc(event.templateDataLength);    
    memcpy(event.hashOfTemplate,hashOfTemplate->data,SHA256_DIGEST_LENGTH);

  //  printf("%u %u %u %u\n",event.pcrIndex,event.templateDataLength,event.templateNameLength,event.templateType);

    
    



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
    
    printf("decodeImaEvents Count: %zu\n", allocatedSize);


    for (size_t i = 0; i < allocatedSize; i++){
        cbor_item_t* arrayItem;
        arrayItem=cbor_array_get(arrayImaEvents, i);
        ImaEventSha256 ev =  decodeImaEvent(arrayItem);
        eventsRef[i] = ev;
    }

    return 0;
}
