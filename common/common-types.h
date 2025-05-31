

#include <cstdint>
#include <openssl/evp.h>
#include <stdint.h>
#include <sys/types.h>
#include <tss2/tss2_tpm2_types.h>
#include <uuid/uuid.h>
#define DEV_ID_LENGTH  38
#define SESSION_ID_MAX_LENGTH  38

enum TrustState {
    TRUSTWORTHY,
    UNTRUSTWORTHY
};

typedef struct ServerSession {
    char deviceId[DEV_ID_LENGTH];
    char sessionId[SESSION_ID_MAX_LENGTH];
    TPM2B_PUBLIC pubKey;        
    uint8_t lastValidAttestation[EVP_MAX_MD_SIZE]; // Is NULL if there never was one
    uint32_t attestLength;
    bool isTrustWorthy; // is set to false by default
    uint64_t lastValidAttestationTimestamp;
    uint64_t lastValidAtestationImaIndex; //This specifies the point at which the last Attestation was valid
    uint8_t sessionHash[EVP_MAX_MD_SIZE];
    uint8_t pcrs[30][EVP_MAX_MD_SIZE];
    
} ServerSession;

