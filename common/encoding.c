#include <cbor.h>
#include <cbor/bytestrings.h>
#include <cbor/common.h>
#include <cbor/data.h>
#include <cbor/serialization.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_tpm2_types.h>
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

int32_t encodePublicKey(TPM2B_PUBLIC* public,uint8_t** serializedOut,size_t* lengthOut) {
    uint8_t buf[1024];
    size_t offset = 0;

    TSS2_RC rc = Tss2_MU_TPM2B_PUBLIC_Marshal(public, buf, sizeof(buf), &offset);
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

