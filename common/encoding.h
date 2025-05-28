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



extern int32_t encodeAttestationCbor( TPM2B_ATTEST attest,TPMT_SIGNATURE signature, uint8_t** serializedOut,size_t* lengthOut);
extern int32_t encodePublicKey(TPM2B_PUBLIC* publicKey,uint8_t** serializedOut,size_t* lengthOut);

extern int32_t decodeAttestationCbor(const uint8_t* cborData,uint32_t cborDataLen, TPM2B_ATTEST* attestOut,TPMT_SIGNATURE* signatureOut);
extern int32_t decodePublicKey(const uint8_t* cborData,uint32_t cborDataLen, TPM2B_PUBLIC* publicKeyOut);

extern int32_t encodeImaEvents(struct ImaEventSha256* events, uint32_t len,uint8_t** serializedOut,size_t* lengthOut);
extern int32_t decodeImaEvents(const uint8_t* cborData,uint32_t cborDataLen, ImaEventSha256** events, size_t* size );