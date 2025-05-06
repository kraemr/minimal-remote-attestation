#ifndef HTTPLIB_H
#define HTTPLIB_H
    #include "../../common/cpp-httplib/httplib.h"
#include <cstddef>
#include <cstdint>
    #include <exception>
    #include <openssl/evp.h>
    #include <openssl/sha.h>
    #include <stdint.h>
#include <string>
    #include <tss2/tss2_common.h>
    #include <tss2/tss2_tpm2_types.h>
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
        std::cout << "Data inserted successfully.\n";
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return 0;
}

// throws out of range exception if sessionId doesnt exist
void getSession(std::map<std::string,ServerSession*>& sessionMap,char* sessionId,ServerSession* sessionRef) {
    std::cout << "getSession: " <<  sessionId  << " " << sessionMap.size() << std::endl;    

    for (const auto& pair : sessionMap) {
        std::cout << "Key: " << pair.first << std::endl;
    }

    sessionRef = sessionMap.at(sessionId);

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

    sqlite3* db; 
    sqlite3_stmt* stmt;
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

// Creates a new Session in the HashMap and adds it to the DB
int32_t initNewSession(std::map<std::string,ServerSession*>& sessionMap,std::string deviceId, std::string sessionId ){
    ServerSession* session = new ServerSession;    
    memcpy(session->deviceId,deviceId.data(), deviceId.size());
    memcpy(session->sessionId,sessionId.data(), sessionId.size());
    session->lastValidAtestationImaIndex = 0;
    session->lastValidAttestation = NULL;
    session->lastValidAttestationTimestamp = 0;
    session->pubKey = NULL;
    memset(session->sessionHash, 0,64);
    memcpy(session->sessionId,sessionId.data(),sessionId.length()+1);
    std::cout << session->sessionId << " " << sessionId.length() << std::endl; 
    std::pair<char*,ServerSession*> p(session->sessionId,session);
    sessionMap.insert(p);
    return 0;
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
        if(content.empty()){
            std::cout << "got no events ?" << std::endl;
            return;
        }
        // Probably would be better to keep a static buffer, that is same size as client, so no memory allocs are actually needed
        ImaEventSha256* events = NULL;
        size_t size = 0;
        int32_t t = decodeImaEvents( (uint8_t*)content.data(), content.size(),&events,&size);
        calculateQuote(events,size,pcrs, CRYPTO_AGILE_SHA256);
        //displayDigest(pcrs[10],SHA256_DIGEST_LENGTH);
        t = writeEventLog("test1",events,size);
        std::string sessionId = req.get_header_value("Session-ID");
        free(events);
        res.set_content("", "application/cbor");
    });

    // Get the Signing Key from the client
    svr.Post("/enroll", [&](const httplib::Request & req, httplib::Response &res) {        
        char out[UUID_STR_LEN+1];
        int32_t r = 0;
        if(req.body.empty()){
            std::cout << "missing keys" << std::endl;
            return;
        }
        uuid(out);
        out[UUID_STR_LEN] = '\0';
        std::cout << "/enroll test strlen " << strlen(out) << std::endl; 

        try{
            r = initNewSession(currentSessions,"DEADBEEFXXXXXXXX",std::string(out));
        }
        catch(std::exception e){
            std::cout << "enroll initNewSession: " << e.what() << std::endl;
        }

        try{            
            ServerSession* session = nullptr; 
            getSession(currentSessions, out, session);
            r = addNewDevice();
         //   memcpy(session->pubKey,req.body.data(),req.body.length());
           // session->pubKeyLength = req.body.length();
         //   r = addSession(session);
        }
        catch(std::exception e){
            std::cout << "enroll getSession: " << e.what() << std::endl;
        }
        

        

        res.set_content("", "text/plain");        
    });

    // Get the quote 
    svr.Post("/quote", [&](const httplib::Request & req, httplib::Response &res) {
        auto content = req.body;
        if(content.empty()){
            std::cout << "missing keys" << std::endl;
            return;
        }
        //auto sigMatch = verifyQuoteSignature(NULL,NULL,NULL);
        std::string sessionId = req.get_header_value("Session-ID");
        res.set_content("", "application/cbor");
    });
    
    std::cout << "Server is running on port 8084" << std::endl;
    if (!svr.listen("0.0.0.0", 8084)) {
        std::cerr << "Error: server failed to start.\n";
    }
}