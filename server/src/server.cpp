#ifndef HTTPLIB_H
#define HTTPLIB_H
    #include "../../common/cpp-httplib/httplib.h"
#include <cstddef>
#include <cstdint>
    #include <exception>
#include <openssl/asn1.h>
    #include <openssl/evp.h>
    #include <openssl/sha.h>
    #include <openssl/buffer.h>
    #include <openssl/bio.h>
    
    #include <stdint.h>
#include <string>
    #include <tss2/tss2_common.h>
#include <tss2/tss2_mu.h>
    #include <tss2/tss2_tpm2_types.h>
#include <utility>
#include <uuid/uuid.h>
#endif

#include "../../common/encoding.h"
#include "../inc/sessions.hpp"
#include "../../common/ima_log_lib/inc/ima_verify.h"
#include "../../common/ima_log_lib/inc/types.h"

#include "../../common/common-types.h"
#include <sqlite3.h>

extern void displayDigest(uint8_t *pcr, int32_t n);
extern int32_t  writeEventLog (const char* path, ImaEventSha256* events, uint32_t length);
extern bool verifyQuoteSignature(TPM2B_PUBLIC pub_key, TPM2B_ATTEST quote, TPMT_SIGNATURE signature);
extern int32_t initSqliteDatabase(const char * scriptPath, const char * dbPath);

void sendErrResponse() {
}

void sendSuccessResponse() {
}


#include <stdio.h>
#include <inttypes.h>

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
    if (session->lastValidAttestation && session->attestLength > 0) {
        print_hex(session->lastValidAttestation, session->attestLength);
        printf("\n");
    } else {
        printf("NULL\n");
    }

    printf("Last Valid Attestation Timestamp: %" PRIu64 "\n", session->lastValidAttestationTimestamp);
    printf("Last Valid Attestation IMA Index: %" PRIu64 "\n", session->lastValidAtestationImaIndex);

    printf("Session Hash: ");
    print_hex(session->sessionHash, EVP_MAX_MD_SIZE);
    printf("\n");
}


int loadServerSession(sqlite3* db, const char* device_id, const char* session_id, ServerSession* session) {
    const char* sql = "SELECT session_id, public_key, quote, last_quote_index "
                      "FROM RemoteAttestationSession WHERE device_id = ? AND session_id = ?";
    sqlite3_stmt* stmt;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
    
    sqlite3_bind_text(stmt, 1, device_id, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, session_id, -1, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        strncpy(session->deviceId, device_id, DEV_ID_LENGTH);
        strncpy(session->sessionId, (const char*)sqlite3_column_text(stmt, 0), SESSION_ID_MAX_LENGTH);

        // public_key
        const void* pubKeyBlob = sqlite3_column_blob(stmt, 1);
        int pubKeyLen = sqlite3_column_bytes(stmt, 1);
        session->pubKey = (uint8_t*)malloc(pubKeyLen);
        memcpy(session->pubKey, pubKeyBlob, pubKeyLen);
        session->pubKeyLength = pubKeyLen;

        // quote
        const void* quoteBlob = sqlite3_column_blob(stmt, 2);
        int quoteLen = sqlite3_column_bytes(stmt, 2);
        if (quoteLen > 0) {
            memcpy(session->lastValidAttestation, quoteBlob, quoteLen);
            session->attestLength = quoteLen;
        } else {        
            session->attestLength = 0;
        }
        session->lastValidAtestationImaIndex = sqlite3_column_int64(stmt, 3);
        sqlite3_finalize(stmt);
        return 0;
    }

    sqlite3_finalize(stmt);
    return -1; // not found or error
}

int updateServerSession(sqlite3* db, const ServerSession* session) {
    const char* sql = "UPDATE RemoteAttestationSession SET "
                      "public_key = ?, quote = ?, last_quote_index = ? "
                      "WHERE device_id = ? AND session_id = ?";
    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;

    sqlite3_bind_blob(stmt, 1, session->pubKey, session->pubKeyLength, SQLITE_STATIC);
    if (session->lastValidAttestation) {
        sqlite3_bind_blob(stmt, 2, session->lastValidAttestation, session->attestLength, SQLITE_STATIC);
    } else {
        sqlite3_bind_null(stmt, 2);
    }
    sqlite3_bind_int64(stmt, 3, session->lastValidAtestationImaIndex);
    sqlite3_bind_int64(stmt, 4, 1);
    sqlite3_bind_text(stmt, 5, session->sessionId, -1, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? 0 : -1;
}

int32_t addNewDevice() {
    char out[UUID_STR_LEN] = {0};
    uuid(out);
    const char* sql = "INSERT INTO DeviceIds(device_id) VALUES(?)";
    sqlite3* db; 
    sqlite3_stmt* stmt;
    sqlite3_open("sesh.db",&db);
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare statement\n";
        sqlite3_close(db);
        return 1;
    }
    sqlite3_bind_text(stmt,0,out,-1,SQLITE_STATIC);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        std::cerr << "Execution failed: " << sqlite3_errmsg(db) << "\n";
    } else {
        std::cout << "inserted new Device Id successfully.\n";
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return 0;
}

int32_t updateSession(std::map<std::string,ServerSession*>& sessionMap,char * sessionId) {



}

// throws out of range exception if sessionId doesnt exist
void getSession(std::map<std::string,ServerSession*>& sessionMap,char* sessionId,ServerSession** sessionRef) {
    if (sessionMap.find(std::string(sessionId)) != sessionMap.end()) {
        (*sessionRef) = sessionMap.at(std::string(sessionId));
        std::cout << "session found nullptr? " << (sessionRef == nullptr)  << std::endl;
    }else{
        std::cout << "session not found" << std::endl;
        sessionRef = nullptr;
    }
}

int32_t addSession(ServerSession* session ) {
    const char* sql = R"(
    INSERT INTO RemoteAttestationSession (
        device_id,
        session_id,
        path_to_log_directory,
        quote,
        public_key,
        last_quote_index
    ) VALUES (?, ?, ?, ?, ?, ?);
    )";
    sqlite3_stmt* stmt;
    sqlite3* db; 
    sqlite3_open("sesh.db",&db);
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare statement\n";
        sqlite3_close(db);
        return 1;
    }

    sqlite3_bind_int(stmt, 1, 1);  // device_id
    sqlite3_bind_text(stmt, 2, session->sessionId, -1, SQLITE_STATIC);  // session_id
    sqlite3_bind_text(stmt, 3, "/logs/device42/", -1, SQLITE_STATIC);        // path_to_log_directory
    sqlite3_bind_null(stmt, 4);
    sqlite3_bind_blob(stmt, 5,session->pubKey, session->pubKeyLength, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 6, 0);  // last_quote_index

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        std::cerr << "Execution failed: " << sqlite3_errmsg(db) << "\n";
    } else {
        std::cout << "Data inserted successfully.\n";
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return 0;
}

void sha256_hash(const unsigned char* data, size_t data_len, unsigned char* out_digest, unsigned int* out_len) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();  // Create context
    if (!ctx) {
        fprintf(stderr, "EVP_MD_CTX_new failed\n");
        return;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        fprintf(stderr, "DigestInit failed\n");
        EVP_MD_CTX_free(ctx);
        return;
    }

    if (EVP_DigestUpdate(ctx, data, data_len) != 1) {
        fprintf(stderr, "DigestUpdate failed\n");
        EVP_MD_CTX_free(ctx);
        return;
    }

    if (EVP_DigestFinal_ex(ctx, out_digest, out_len) != 1) {
        fprintf(stderr, "DigestFinal failed\n");
        EVP_MD_CTX_free(ctx);
        return;
    }

    EVP_MD_CTX_free(ctx);
}

int sha256_base64(const unsigned char* data, size_t data_len, char* out_b64, size_t out_b64_len) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, data_len);
    EVP_DigestFinal_ex(ctx, hash, &hash_len);
    EVP_MD_CTX_free(ctx);

    // Create base64 BIO chain
    BIO* bio, * b64;
    BUF_MEM* bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    BIO_push(b64, bio);

    // Disable newlines
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    BIO_write(b64, hash, hash_len);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bufferPtr);

    if (bufferPtr->length + 1 > out_b64_len) {
        BIO_free_all(b64);
        return -1; // Buffer too small
    }

    memcpy(out_b64, bufferPtr->data, bufferPtr->length);
    out_b64[bufferPtr->length] = '\0';

    BIO_free_all(b64);
    return 0;
}

// Creates a new Session in the HashMap and adds it to the DB
int32_t initNewSession(std::map<std::string,ServerSession*>& sessionMap,std::string deviceId, std::string sessionId ){
    ServerSession* session = new ServerSession;    
    memcpy(session->deviceId,deviceId.data(), deviceId.size());
    memcpy(session->sessionId,sessionId.data(), sessionId.size());
    session->lastValidAtestationImaIndex = 0;        
    session->lastValidAttestationTimestamp = 0;
    session->pubKey = NULL;
    
    memset(session->sessionHash, 0,64);
    memcpy(session->sessionId,sessionId.data(),sessionId.length()+1);    
    std::pair<char*,ServerSession*> p(session->sessionId,session);
    
    sessionMap.insert(p);
    return 0;
}

/*
Step 1: Check that we have the expected pcrSelection, for now its just 10
Step 2: recalculate the quote
*/
int32_t verifyQuote(TPMS_ATTEST* attestation, ServerSession* session) {    
    TPM2B_DIGEST digest = attestation->attested.quote.pcrDigest;
    TPML_PCR_SELECTION pcrSelection = attestation->attested.quote.pcrSelect;
    if (session->attestLength == 0) {    
        // For Testing : 
        const char * path = "test1";
        int fd = 0;
        fd = open(path,O_RDONLY);        
        ImaEventSha256 buffer[100];        
        uint8_t pcrs[30][EVP_MAX_MD_SIZE];
        uint64_t count = 0;        
        
        std::cout << "verifyQuote attestation: ";
        print_hex(attestation->attested.quote.pcrDigest.buffer, attestation->attested.quote.pcrDigest.size);
        std::cout << std::endl;
        uint8_t temp[EVP_MAX_MD_SIZE];
        do {        
            count = readImaLog(fd,CRYPTO_AGILE_SHA256,buffer,100);
            for (uint32_t i = 0; i < count ; i++) {
                calculateQuote(&buffer[i],1,pcrs, CRYPTO_AGILE_SHA256);
                EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
                uint32_t out = 0;
                
                EVP_DigestInit_ex((mdctx), EVP_sha256(), NULL);		        
                EVP_DigestUpdate(mdctx,pcrs[10] ,SHA256_DIGEST_LENGTH);	                
                EVP_DigestFinal_ex(mdctx, temp, &out);
                EVP_MD_CTX_free(mdctx);

                if( memcmp( temp,attestation->attested.quote.pcrDigest.buffer,SHA256_DIGEST_LENGTH ) != 0 ) {
                    //Fail
                    
                }
                else {
                    //Success
                    std::cout << "verifyQuote: Success" << std::endl;
                }
            }
            
        }while( count );
        std::cout << " verifyQuote: couldnt find any IMA Event at which the Hash Matches " << std::endl;
        /*
            getPathImaEventsFile
            readImaEvents and calculateQuote

        */
    }
    // Recalculate from the lastValidAttestationIndex and use the lastValidAttestation as a baseline
    else{

    }
}

int main() {
    httplib::Server svr;
    const uint8_t zeroed[EVP_MAX_MD_SIZE] = {0};
    uint8_t pcrs[30][EVP_MAX_MD_SIZE];
    std::map<std::string,ServerSession*> currentSessions;
    for(int i = 0; i< 30; i++){
        memmove(pcrs[i],zeroed,EVP_MAX_MD_SIZE);
    }
    uint32_t s = initSqliteDatabase("src/db/init.sql","sesh.db");

    svr.Post("/ima", [&](const httplib::Request & req, httplib::Response &res) {       
        auto content = req.body;        
        char sessionId[UUID_STR_LEN+1] = "7ebad9a7-57f5-4ce6-9785-e42cadf7373e\0";
        ServerSession* session = nullptr;         
        if(content.empty()){
            std::cout << "got no events ?" << std::endl;
            return;
        }
        getSession(currentSessions,sessionId,&session);

        // Probably would be better to keep a static buffer, that is same size as client, so no memory allocs are actually needed
        ImaEventSha256* events = NULL;
        size_t size = 0;
        int32_t t = decodeImaEvents( (uint8_t*)content.data(), content.size(),&events,&size);

        //calculateQuote(events,size,pcrs, CRYPTO_AGILE_SHA256);
        for (int i = 0; i < size; i++) {
            int32_t res = verifyQuoteStep(&events[i],pcrs,session->lastValidAttestation);
            if(res) {
                std::cout << "QUOTE DIGEST MATCHES " << std::endl;
            }
        }
        //print_hex(pcrs[10],SHA256_DIGEST_LENGTH);
     //   t = writeEventLog("test1",events,size);
        //std::string sessionId = req.get_header_value("Session-ID");
        free(events);
        res.set_content("", "application/cbor");
    });

    // Get the Signing Key from the client
    svr.Post("/enroll", [&](const httplib::Request & req, httplib::Response &res) {      
        std::cout << "entroll" << std::endl;  
        int32_t r = 0;
        char sessionId[UUID_STR_LEN+1] = "7ebad9a7-57f5-4ce6-9785-e42cadf7373e\0";
        char* deviceId = (char*)malloc(SHA256_DIGEST_LENGTH * 3);
        uint32_t outLen = 0;
        ServerSession* session = nullptr;         

        if(req.body.empty()){
            std::cout << "missing public key" << std::endl;
            return;
        }                
        sha256_base64((uint8_t*)req.body.data(),req.body.length(),deviceId,SHA256_DIGEST_LENGTH * 3);
        //uuid(sessionId);
        //std::cout << deviceId << " session_id: " << sessionId  << std::endl;        
        //try{
            //r = initNewSession(currentSessions,deviceId,std::string(out));
        //}
        //catch(std::exception e){
           // std::cout << "enroll initNewSession: " << e.what() << std::endl;
        //}
        getSession(currentSessions,sessionId,&session);        
        if( session == nullptr){                                
            std::cout << "session == nullptr" << std::endl;                    
            sqlite3* db; 
            sqlite3_open("sesh.db",&db);              
            session = new ServerSession();      
            loadServerSession(db,deviceId,sessionId,session);
            session->pubKeyLength = req.body.length();         
            session->pubKey = (uint8_t*)malloc(req.body.length());
            memcpy(session->sessionId,sessionId,37);
            memcpy(session->pubKey,req.body.data(),req.body.length());
            memcpy(session->deviceId,deviceId,outLen);                

            //print_server_session(session);         
            
            std::pair<char*,ServerSession*> p(session->sessionId,session);
            currentSessions.insert(p);  
                              
        }
        else{
            std::cout << "resuming session: " << sessionId << std::endl;        
        }                    
        res.set_content(sessionId, "text/plain");        
    });

    // Get the quote 
    svr.Post("/quote", [&](const httplib::Request & req, httplib::Response &res) {
        auto content = req.body;        
        char sessionId[UUID_STR_LEN+1] = "7ebad9a7-57f5-4ce6-9785-e42cadf7373e\0";
        ServerSession* session = nullptr;
        if(content.empty()){
            std::cout << "missing keys" << std::endl;
            return;
        }
        getSession(currentSessions,sessionId,&session);
        if(session == nullptr ){
            sendErrResponse();
            return;            
        }
        TPM2B_PUBLIC keyInfo = {};
        TPM2B_ATTEST attest_blob = {};
        TPMT_SIGNATURE signature;
        TPMS_ATTEST attest;        
        size_t offset = 0;                                
        int32_t result = decodeAttestationCbor((uint8_t*)req.body.data(),req.body.length(),&attest_blob,&signature);        
        int32_t rc = decodePublicKey((uint8_t*)session->pubKey, session->pubKeyLength, &keyInfo);                
        
        if(rc != TSS2_RC_SUCCESS){
            std::cout << "Tss2_MU_TPM2B_PUBLIC_Unmarshal failed " << rc << std::endl;
            return;
        }
       
        bool b = verifyQuoteSignature(keyInfo,attest_blob,signature);
        if (!b) {            
            return;
        }

        rc = Tss2_MU_TPMS_ATTEST_Unmarshal(
            attest_blob.attestationData,
            attest_blob.size,
            &offset,
            &attest
        );
        std::cout << "QUOTE_DIGEST: ";
        print_hex(attest.attested.quote.pcrDigest.buffer,attest.attested.quote.pcrDigest.size);
        std::cout << std::endl;
        session->attestLength = attest.attested.quote.pcrDigest.size;
        memcpy( session->lastValidAttestation,attest.attested.quote.pcrDigest.buffer, attest.attested.quote.pcrDigest.size );
        res.set_content("", "text/plain");
    });
    
    std::cout << "Server is running on port 8084" << std::endl;
    if (!svr.listen("0.0.0.0", 8084)) {
        std::cerr << "Error: server failed to start.\n";
    }
}