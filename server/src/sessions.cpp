#include "../inc/sessions.hpp"
#include "../../common/encoding.h"
#include <sqlite3.h>
#include <iostream>


char* uuid(char out[UUID_STR_LEN]){
  uuid_t b;
  uuid_generate(b);
  uuid_unparse_lower(b, out);
  return out;
}

void print_hex(const uint8_t* data, uint32_t length) {
    for (uint32_t i = 0; i < length; ++i) {
        printf("%x", data[i]);
    }
}

void print_server_session(const ServerSession* session) {
    printf("=== ServerSession ===\n");
    printf("Device ID: %s\n", session->deviceId);
    printf("Session ID: %s\n", session->sessionId);

    printf("Public Key Length: %u bytes\n", session->pubKeyLength);
    printf("Public Key: ");
    if (session->pubKey && session->pubKeyLength > 0) {
        print_hex(session->pubKey, session->pubKeyLength);
        printf("\n");
    } else {
        printf("NULL\n");
    }

    printf("Attestation Length: %u bytes\n", session->attestLength);
    printf("Last Valid Attestation: ");
    if (session->attestLength > 0) {
        print_hex(session->lastValidAttestation, session->attestLength);
        printf("\n");
    } else {
        printf("NULL\n");
    }

    printf("Last Valid Attestation Timestamp: %lu \n", session->lastValidAttestationTimestamp);
    printf("Last Valid Attestation IMA Index: %lu \n", session->lastValidAtestationImaIndex);

    printf("Session Hash: ");
    print_hex(session->sessionHash, EVP_MAX_MD_SIZE);
    printf("\n");
}



