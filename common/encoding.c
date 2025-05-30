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
#include <stdio.h>
#include <string.h>

#include <tss2/tss2_mu.h>
#include <tss2/tss2_tpm2_types.h>
#include <tss2/tss2_common.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_sys.h>
#include "../common/ima_log_lib/inc/ima_template_parser.h"
#include "../common/ima_log_lib/inc/ima_verify.h"
#include "ima_log_lib/inc/types.h"
#include "libcbor/src/cbor/arrays.h"
extern void displayDigest(uint8_t *pcr, int32_t n);

size_t encode_cred_to_cbor(
                        const unsigned char* session_id,
                        unsigned int session_id_len,
                        TPM2B_ID_OBJECT *cred, 
                        TPM2B_ENCRYPTED_SECRET *secret, 
                        unsigned char **out_buffer) {
    
    cbor_item_t *map = cbor_new_definite_map(3);

    int res = cbor_map_add(map, (struct cbor_pair) {
        .key = cbor_move(cbor_build_string("cred")),
        .value = cbor_move(cbor_build_bytestring(cred->credential, cred->size))
    });

    res = cbor_map_add(map, (struct cbor_pair) {
        .key = cbor_move(cbor_build_string("secret")),
        .value = cbor_move(cbor_build_bytestring(secret->secret, secret->size))
    });
    
    res = cbor_map_add(map, (struct cbor_pair) {
        .key = cbor_move(cbor_build_string("session_id")),
        .value = cbor_move(cbor_build_bytestring(session_id, session_id_len))
    });

    size_t buffer_size=0;
    size_t packed_size = cbor_serialize_alloc(map, out_buffer, &buffer_size);
    cbor_decref(&map); // Correct API for ref count
    return packed_size;
}


cbor_item_t* find_in_map(cbor_item_t *map, const char *key_str) {
    size_t map_size = cbor_map_size(map);
    struct cbor_pair *handle = cbor_map_handle(map);
    size_t key_len = strlen(key_str);

    for (size_t i = 0; i < map_size; i++) {
        if (cbor_isa_string(handle[i].key)) {
            size_t current_len = cbor_string_length(handle[i].key);
            const char *current_key =
                (const char *)cbor_string_handle(handle[i].key);

            if (current_len == key_len &&
                memcmp(current_key, key_str, key_len) == 0) {
                return handle[i].value;
            }
        }
    }
    return NULL;
}

int decode_cred_from_cbor(unsigned char *cbor_data, 
                          size_t cbor_len, 
                          TPM2B_ID_OBJECT *out_cred, 
                          TPM2B_ENCRYPTED_SECRET *out_secret,
                          unsigned char* session_id,
                          unsigned int* session_id_len){
    struct cbor_load_result result;
    cbor_item_t *map = cbor_load(cbor_data, cbor_len, &result);

    if (!map || !cbor_isa_map(map)) {
        if (map) cbor_decref(&map);
        return -1;
    }
    
    cbor_item_t *cred_item = find_in_map(map, "cred");
    if (cred_item && cbor_isa_bytestring(cred_item)) {
        out_cred->size = cbor_bytestring_length(cred_item);
        memcpy(out_cred->credential, cbor_bytestring_handle(cred_item), out_cred->size);
    }
    
    cbor_item_t *sec_item = find_in_map(map, "secret");
    if (sec_item && cbor_isa_bytestring(sec_item)) {
        out_secret->size = cbor_bytestring_length(sec_item);
        memcpy(out_secret->secret, cbor_bytestring_handle(sec_item), out_secret->size);
    }

    cbor_item_t *sesh_item = find_in_map(map, "session_id");
    if (sec_item && cbor_isa_bytestring(sec_item)) {
        (*session_id_len) = cbor_bytestring_length(sesh_item);
        memcpy(session_id, cbor_bytestring_handle(sesh_item), *session_id_len);
    }
    cbor_decref(&map);
    return 0;
}

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


// Enroll
int32_t encodePublicKey(
    TPM2B_PUBLIC* publicKey,
    TPM2B_ATTEST* attest,
    TPMT_SIGNATURE* signature,
    const uint8_t* ekCert,
    size_t ekCertLen,
    uint8_t** serializedOut,
    size_t* lengthOut)
{
    cbor_item_t* arr = cbor_new_definite_array(4);    
    uint8_t buf[1024];
    size_t offset = 0;
    TSS2_RC rc = Tss2_MU_TPM2B_PUBLIC_Marshal(publicKey, buf, sizeof(buf), &offset);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to marshal TPM2B_PUBLIC: 0x%x\n", rc);
        return rc;
    }
    int res = cbor_array_push(arr, cbor_build_bytestring(buf, offset));
    
    rc = Tss2_MU_TPMT_SIGNATURE_Marshal(signature,buf,sizeof(buf),&offset);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to marshal TPMT_SIGNATURE: 0x%x\n", rc);
        return rc;
    }
    res = cbor_array_push(arr, cbor_build_bytestring(buf, offset));
    
    rc = Tss2_MU_TPM2B_ATTEST_Marshal(attest, buf, sizeof(buf), &offset);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to marshal TPMT_SIGNATURE: 0x%x\n", rc);
        return rc;
    }
    res = cbor_array_push(arr, cbor_build_bytestring(buf, offset));
    res = cbor_array_push(arr, cbor_build_bytestring(ekCert, ekCertLen));

    cbor_serialize_alloc(arr, serializedOut, lengthOut);
    cbor_decref(&arr);
    return rc;
}

int32_t decodePublicKey(
    const uint8_t* cborData,
    size_t cborDataLen,
    TPM2B_PUBLIC* publicKeyOut,
    TPM2B_ATTEST* attestOut,
    TPMT_SIGNATURE* signatureOut,
    uint8_t** ekCertOut,
    size_t* ekCertLenOut)
{
    struct cbor_load_result result;
    cbor_item_t* root = cbor_load(cborData, cborDataLen, &result);

    if (!root || !cbor_isa_array(root) || cbor_array_size(root) != 4) {
        fprintf(stderr, "Expected CBOR array of 4 elements\n");
        if (root) cbor_decref(&root);
        return -1;
    }

    cbor_item_t* pubKeyItem = cbor_array_get(root, 0);
    cbor_item_t* signatureItem = cbor_array_get(root, 1);
    cbor_item_t* attestItem = cbor_array_get(root, 2);    
    cbor_item_t* certItem = cbor_array_get(root, 3);

    if (!cbor_isa_bytestring(pubKeyItem) || !cbor_isa_bytestring(certItem) || !cbor_isa_bytestring(signatureItem) || !cbor_isa_bytestring(attestItem)) {
        fprintf(stderr, "Both array elements must be bytestrings\n");
        cbor_decref(&root);
        return -1;
    }

    // Unmarshal TPM2B_PUBLIC
    const uint8_t* pubBuf = cbor_bytestring_handle(pubKeyItem);
    size_t pubLen = cbor_bytestring_length(pubKeyItem);
    size_t offset = 0;
    TSS2_RC rc = Tss2_MU_TPM2B_PUBLIC_Unmarshal(pubBuf, pubLen, &offset, publicKeyOut);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to unmarshal TPM2B_PUBLIC: 0x%x\n", rc);
        cbor_decref(&root);
        return rc;
    }

    rc = Tss2_MU_TPMT_SIGNATURE_Unmarshal(cbor_bytestring_handle(signatureItem),cbor_bytestring_length(signatureItem) , &offset, signatureOut);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to unmarshal TPMT_SIGNATURE: 0x%x\n", rc);
        cbor_decref(&root);
        return rc;
    }


    rc = Tss2_MU_TPM2B_ATTEST_Unmarshal(cbor_bytestring_handle(attestItem),cbor_bytestring_length(attestItem) , &offset, attestOut);
    if (rc != TSS2_RC_SUCCESS) {
        fprintf(stderr, "Failed to unmarshal TPM2B_PUBLIC: 0x%x\n", rc);
        cbor_decref(&root);
        return rc;
    }

    // Copy EK cert
    *ekCertLenOut = cbor_bytestring_length(certItem);
    *ekCertOut = malloc(*ekCertLenOut);
    if (!*ekCertOut) {
        fprintf(stderr, "Memory allocation for EK cert failed\n");
        cbor_decref(&root);
        return -2;
    }
    memcpy(*ekCertOut, cbor_bytestring_handle(certItem), *ekCertLenOut);
    cbor_decref(&root);
    return 0;
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

