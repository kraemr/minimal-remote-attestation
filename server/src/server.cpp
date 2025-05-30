#ifndef HTTPLIB_H
#define HTTPLIB_H
    #include "../../common/cpp-httplib/httplib.h"    
#endif
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
#include "../../common/encoding.h"
#include "../inc/sessions.hpp"
#include "../../common/ima_log_lib/inc/ima_verify.h"
#include "../../common/ima_log_lib/inc/types.h"
#include <stdio.h>

extern void displayDigest(uint8_t *pcr, int32_t n);
extern int32_t  writeEventLog (const char* path, ImaEventSha256* events, uint32_t length);
extern bool verifyQuoteSignature(TPM2B_PUBLIC pub_key, TPM2B_ATTEST quote, TPMT_SIGNATURE signature);
extern int32_t verifyEkCertificate(const char *root_bundle_path, uint8_t* ekCertificate, size_t ekCertLen );

void sendErrResponse() {
}

void sendSuccessResponse() {
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


// returns a session_id if it was set by the client
// maybe return session object from here ?
std::string handleSessionHeaders(const httplib::Request & req, httplib::Response &res) {
    //std::string sessionId = req.get_header_value("Session-ID");
    std::string sessionId = "7ebad9a7-57f5-4ce6-9785-e42cadf7373e";
    return sessionId;
}

// /ima
void handleIma(std::map<std::string, ServerSession*>& sessionMap,const httplib::Request & req, httplib::Response &res) {    
    ServerSession* session = nullptr;         
    ImaEventSha256* events;
    size_t size = 0;    
    if(req.body.empty()) return;
    std::string sessionId = handleSessionHeaders(req, res);
    getSession(sessionMap,sessionId.data(),&session);        
    int32_t ret = decodeImaEvents( (uint8_t*)req.body.data(), req.body.size(),&events,&size);    
    std::cout << "session == nullptr: " << (session == nullptr) << " handleIma size: " << size << std::endl;
    
    for (int i = 0; i < size; i++) {        
        if(verifyQuoteStep(&events[i],session->pcrs,session->lastValidAttestation)) std::cout << "QUOTE DIGEST MATCHES " << std::endl;    
    }            
    res.set_content("", "application/cbor");
}

void handleEnroll(std::map<std::string, ServerSession*>& sessionMap,const httplib::Request & req, httplib::Response &res) {
        int32_t r = 0;
        std::string sessionId = handleSessionHeaders(req,res);
        uint32_t outLen = 0;
        uint8_t* data = nullptr;
        ServerSession* session = nullptr;         
        if(req.body.empty()){
            std::cout << "missing public key" << std::endl;
            return;
        }                
        const char* deviceId = "DEADBEEF";
        //sha256_base64((uint8_t*)req.body.data(),req.body.length(),deviceId,SHA256_DIGEST_LENGTH * 3);
        //uuid(sessionId.data());
        //std::cout << deviceId << " session_id: " << sessionId  << std::endl;        
        //try{
            //r = initNewSession(currentSessions,deviceId,std::string(out));
        //}
        //catch(std::exception e){
           // std::cout << "enroll initNewSession: " << e.what() << std::endl;
        //}
        TPM2B_PUBLIC pubKey;
        uint8_t* ekCert = nullptr;
        size_t ekCertLen = 0;

        std::cout<< "handleEnroll request len: " << req.body.length() << std::endl;
        r = decodePublicKey((uint8_t*)req.body.data(),req.body.length(),&pubKey,&ekCert,&ekCertLen);
        
        std::cout << "pubKey: " << pubKey.size << std::endl;

        if (r != 0){
            // decodePubKey failed
            //return;
            std::cout << "handleEnroll decodePublicKey failed " <<  std::endl;
        }
        r = verifyEkCertificate("../root-certs/root_bundle.pem",ekCert,ekCertLen );
        if(!r) {
            // EKCert is not to be trusted
            //return;
            std::cout << "handleEnroll verifyEkCert failed" << std::endl;
        }

        getSession(sessionMap,sessionId.data(),&session);        
        if( session == nullptr){                                            
            Database* db = new Database("sesh.db");            
            session = new ServerSession();      
            db->loadServerSession(deviceId, sessionId.c_str(),session);            
            session->pubKeyLength = req.body.length();         
            session->pubKey = (uint8_t*)malloc(req.body.length());
            memcpy(session->sessionId,sessionId.data(),37);
            memcpy(session->pubKey,req.body.data(),req.body.length());
            memcpy(session->deviceId,deviceId,outLen);                                        
            std::pair<char*,ServerSession*> p(session->sessionId,session);
            sessionMap.insert(p);                                
        }
        else{
            std::cout << "resuming session: " << sessionId << std::endl;        
        }                    
        res.set_content(sessionId, "text/plain");        
}

void handleQuote(std::map<std::string, ServerSession*>& sessionMap,const httplib::Request & req, httplib::Response &res) {
        auto content = req.body;        
        ServerSession* session = nullptr;        
        if(content.empty()){
            std::cout << "missing keys" << std::endl;
            return;
        }
        std::string sessionId = handleSessionHeaders(req, res);
        getSession(sessionMap,sessionId.data(),&session);
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
        int32_t rc = decodePublicKey((uint8_t*)session->pubKey, session->pubKeyLength, &keyInfo,NULL,NULL);                
        
        if(rc != TSS2_RC_SUCCESS){
            std::cout << "Tss2_MU_TPM2B_PUBLIC_Unmarshal failed " << rc << std::endl;
            return;
        }
       
        bool signatureMatch = verifyQuoteSignature(keyInfo,attest_blob,signature);
        if (!signatureMatch) {            
            return;
        }

        rc = Tss2_MU_TPMS_ATTEST_Unmarshal(
            attest_blob.attestationData,
            attest_blob.size,
            &offset,
            &attest
        );
      //  std::cout << "QUOTE_DIGEST: ";
      //  print_hex(attest.attested.quote.pcrDigest.buffer,attest.attested.quote.pcrDigest.size);
      //  std::cout << std::endl;
        session->attestLength = attest.attested.quote.pcrDigest.size;
        memcpy( session->lastValidAttestation,attest.attested.quote.pcrDigest.buffer, attest.attested.quote.pcrDigest.size );
        res.set_content("", "text/plain");
}

void zeroPcrs(uint8_t pcrs[30][EVP_MAX_MD_SIZE]) {
    const uint8_t zeroed[EVP_MAX_MD_SIZE] = {0};
    for(int i = 0; i< 30; i++){
        memmove(pcrs[i],zeroed,EVP_MAX_MD_SIZE);
    }
}


int main() {
    httplib::Server svr;
    std::map<std::string,ServerSession*> currentSessions;            
    (new Database("sesh.db"))->initFromScript("src/db/init.sql");
    
    svr.Post("/ima", [&](const httplib::Request & req, httplib::Response &res) {       
        handleIma(currentSessions,req,res);
    });

    // Get the Signing Key from the client
    svr.Post("/enroll", [&](const httplib::Request & req, httplib::Response &res) {      
        handleEnroll(currentSessions, req,res);
    });

    // Get the quote 
    svr.Post("/quote", [&](const httplib::Request & req, httplib::Response &res) {
        handleQuote(currentSessions,req,res);
    });
    
    std::cout << "Server is running on port 8084" << std::endl;
    if (!svr.listen("0.0.0.0", 8084)) {
        std::cerr << "Error: server failed to start.\n";
    }
}