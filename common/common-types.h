

#include <cstdint>
#include <openssl/evp.h>
#include <sys/types.h>
#include <tss2/tss2_tpm2_types.h>
#include <uuid/uuid.h>
#define DEV_ID_LENGTH  38
#define SESSION_ID_MAX_LENGTH  38
typedef struct ServerSession {
    char deviceId[DEV_ID_LENGTH];
    char sessionId[SESSION_ID_MAX_LENGTH];
    uint8_t* pubKey;
    uint32_t pubKeyLength;
    
    uint8_t lastValidAttestation[EVP_MAX_MD_SIZE]; // Is NULL if there never was one
    uint32_t attestLength;

    uint64_t lastValidAttestationTimestamp;
    uint64_t lastValidAtestationImaIndex; //This specifies the point at which the last Attestation was valid
    uint8_t sessionHash[EVP_MAX_MD_SIZE];
} ServerSession;

