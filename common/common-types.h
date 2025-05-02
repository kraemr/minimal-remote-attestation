

#include <cstdint>
#include <openssl/evp.h>
#include <sys/types.h>
#include <tss2/tss2_tpm2_types.h>
#include <uuid/uuid.h>

#define DEV_ID_LENGTH  128
#define SESSION_ID_MAX_LENGTH  128

// TODO:: Add a device ID
struct ServerSession {
    char deviceId[DEV_ID_LENGTH];
    char sessionId[SESSION_ID_MAX_LENGTH]; // uuid should be nul terminated !
    TPM2B_PUBLIC pubKey;
    TPMS_ATTEST* lastValidAttestation; // Is NULL if there never was one
    uint64_t lastValidAttestationTimestamp;
    uint64_t lastValidAtestationImaIndex; //This specifies the point at which the last Attestation was valid
    uint8_t sessionHash[EVP_MAX_MD_SIZE];
};

