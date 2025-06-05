#ifndef HTTPLIB_H
#define HTTPLIB_H
    #include "../../common/cpp-httplib/httplib.h"    
#include <unordered_map>
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
#include <stdio.h>
#include <thread>

#include "../inc/log.hpp"
#include "../inc/sessions.hpp"
#include "../inc/whitelist.hpp"

#include "../../common/encoding.h"
#include "../../common/ima_log_lib/inc/ima_verify.h"
#include "../../common/ima_log_lib/inc/ima_template_parser.h"
#include "../../common/ima_log_lib/inc/types.h"




extern void displayDigest(uint8_t *pcr, int32_t n);
extern int32_t  writeEventLog (const char* path, ImaEventSha256* events, uint32_t length);
extern bool verifyQuoteSignature(TPM2B_PUBLIC pub_key, TPM2B_ATTEST quote, TPMT_SIGNATURE signature);
extern int32_t verifyEkCertificate(const char *root_bundle_path, uint8_t* ekCertificate, size_t ekCertLen );
std::map<std::string,ServerSession*> currentSessions;            

void sendErrResponse() {
}

void sendSuccessResponse() {
}

#include <iostream>
#include <iomanip>
#include <sstream>
#include <openssl/sha.h>

std::string sha256(uint8_t* data, size_t len) {
    std::cout << "sha256: " << len << std::endl;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(data, len, hash);

    std::ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    return oss.str();
}

// throws out of range exception if sessionId doesnt exist
void getSession(std::map<std::string,ServerSession*>& sessionMap,char* sessionId,ServerSession** sessionRef) {
    if (sessionMap.find(std::string(sessionId)) != sessionMap.end()) {
        (*sessionRef) = sessionMap.at(std::string(sessionId));
        //std::cout << "session found nullptr? " << (sessionRef == nullptr)  << std::endl;
    }else{
        //std::cout << "session not found" << std::endl;
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
    memset(session->sessionHash, 0,64);
    memcpy(session->sessionId,sessionId.data(),sessionId.length()+1);    
    memset(session->pcrs[10],0,64);     
    std::pair<char*,ServerSession*> p(session->sessionId,session);    
    sessionMap.insert(p);
    return 0;
}


// returns a session_id if it was set by the client
std::string handleSessionHeaders(const httplib::Request & req, httplib::Response &res) {
    //std::string sessionId = req.get_header_value("Session-ID");
    std::string sessionId = "7ebad9a7-57f5-4ce6-9785-e42cadf7373e";
    return sessionId;
}


bool checkSessionTrustworthiness(ServerSession* sesion) {
    if(sesion == nullptr){
        return false;
    }
    bool trustwothy = sesion->isQuoteTrusted && sesion->isAkTrusted && sesion->isEKTrusted && sesion->isMeasurementsTrusted;        
    return trustwothy;
}

bool checkMeasurementsAreWhitelisted(ServerSession* session, const ImaEventSha256* events, size_t length ) {
    const char * pathWhitelist = "whitelist"; 
    // In Future sessions could also have their own specific whitelists associated to Devices
    std::unordered_map<std::string, FileInformation> whitelist;
    readWhitelist(pathWhitelist, whitelist);
    
    for(size_t i = 0; i < length; i++) { 
        const ImaEventSha256* event = &events[i];
        if(events[i].templateDataLength == 0  ){
            std::cout << "One event did not have templateData ? " << std::endl;
            return false;
        }
        Ima_ng fileMeasurement;
        int32_t success = parseTemplateImaNg(event->templateData, event->templateDataLength, &fileMeasurement);        
     //  std::cout << fileMeasurement.fileName; displayDigest(fileMeasurement.hash,fileMeasurement.hashLength);
        success = checkFilePathWhitelistSha256(fileMeasurement.fileName,fileMeasurement.hash,whitelist);
        if( success == false ){
            session->isMeasurementsTrusted = false;
        }

    }
    return false;
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
    session->isMeasurementsTrusted = false;

    for (int i = 0; i < size; i++) {                                
        uint8_t zeroes[EVP_MAX_MD_SIZE];
        memset(zeroes,0,EVP_MAX_MD_SIZE);       
        // if at some point the measurements match the quote, it is trustworthy
        if(
            session->isMeasurementsTrusted == false &&
            verifyQuoteStep(&events[i],session->pcrs,session->lastValidAttestation) 
            )
        {
            session->isMeasurementsTrusted = true;        
            checkSessionTrustworthiness(session);    
        }
    }            
    checkMeasurementsAreWhitelisted(session,events,size);   

    // if(checkSessionTrustworthiness(session)){
    //     writeLogMessage(ATTESTATION_SUCCESS,"Measurements valid session TRUSTWORTHY",req.remote_addr,sessionId,session->deviceId);
    // }else{
    //     writeLogMessage(ATTESTATION_FAILURE,"Measurements valid session UNTRUSTWORTHY",req.remote_addr,sessionId,session->deviceId);
    // }    

    free(events);
    res.set_content("", "application/cbor");
}

void handleEnroll(std::map<std::string, ServerSession*>& sessionMap,const httplib::Request & req, httplib::Response &res) {
        std::string sessionId = handleSessionHeaders(req,res);
        std::string deviceId;    
        
        int32_t r = 0;        
        uint8_t* data = nullptr;
        ServerSession* session = nullptr;         
        
        if(req.body.empty()){
            std::cout << "missing public key" << std::endl;
            return;
        }                
        
        TPM2B_PUBLIC pubKey;
        TPMT_SIGNATURE signature;
        TPM2B_ATTEST attest;
        uint8_t* ekCert = nullptr;
        size_t ekCertLen = 0;        

        r = decodePublicKey((uint8_t*)req.body.data(),req.body.length(),&pubKey,&attest,&signature,&ekCert,&ekCertLen);            
        if (r != 0){            
            writeLogMessage(ERROR,"Attestation Key is invalid",req.remote_addr,sessionId,"");
            return;
        }

        r = verifyEkCertificate("../root-certs/root_bundle.pem",ekCert,ekCertLen);
        if(!r) {           
            writeLogMessage(ERROR,"EK Cert is invalid",req.remote_addr,sessionId,session->deviceId);
            return;
        }

        bool signatureMatch = verifyQuoteSignature(pubKey,attest,signature);
        if(signatureMatch){
            std::cout << "verifyQuoteSignature succeeded! " << std::endl;                        
        }else{
            std::cout << "verifyQuoteSignature MISMATCH! " << std::endl;      
            return;      
        }

        getSession(sessionMap,sessionId.data(),&session);        
        if( session == nullptr){                     
            deviceId = sha256(ekCert,ekCertLen);
            std::cout << deviceId.length() << std::endl; 

            Database* db = new Database("sesh.db");            
            session = new ServerSession();      
            
            db->loadServerSession(deviceId.c_str(), sessionId.c_str(),session);            
            
            memcpy(session->sessionId,sessionId.data(),37);
            
            session->pubKey = pubKey;
            
            memcpy(session->deviceId,deviceId.c_str(),deviceId.length());
            session->deviceId[64] = '\0';                                       
            std::pair<char*,ServerSession*> p(session->sessionId,session);
            
            session->isAkTrusted = true;
            session->isEKTrusted = true;

            sessionMap.insert(p);                                
        }
        else{
            std::cout << "resuming session: " << sessionId << std::endl;        
        }                    
        res.set_content(sessionId, "text/plain");        
}

// TODO FIND OVERFLOW ERROR HERE
bool checkQuoteFreshness(ServerSession* session, TPMS_ATTEST quote) {
    // Defines the amount a quote can come later/earlier than the specified timeframe
    const int64_t allowedDrift = 6000;
    const int64_t timeFrame = 60000; // one minute in ms

    std::cout << " quote clock: " << quote.clockInfo.clock << std::endl;
    std::cout << " last valid attest" << session->lastValidAttestationTimestamp  << std::endl;

    bool isMonotonic = (quote.clockInfo.clock > session->lastValidAttestationTimestamp);
    int64_t timeDiff = (quote.clockInfo.clock - session->lastValidAttestationTimestamp);
    // Old Quote was used
    if(timeDiff < 0){
        return false;
    }

    bool isWithinTimeFrame = (abs(timeDiff - timeFrame) < allowedDrift);
    session->lastValidAttestationTimestamp = quote.clockInfo.clock;
    return isMonotonic && isWithinTimeFrame;
}

void handleQuote(std::map<std::string, ServerSession*>& sessionMap,const httplib::Request & req, httplib::Response &res) {
        auto content = req.body;        
        ServerSession* session = nullptr;               
        std::string sessionId = handleSessionHeaders(req, res);
        getSession(sessionMap,sessionId.data(),&session);
         
        if(session == nullptr ) {
            writeLogMessage(ERROR,"No session",req.remote_addr,sessionId,session->deviceId);
            sendErrResponse();
            return;            
        }
        session->isQuoteTrusted = false;
        if(content.empty()){            
            writeLogMessage(ERROR,"Quote was empty",req.remote_addr,sessionId,session->deviceId);
            return;
        }
        
        size_t offset = 0;                                
        TPM2B_PUBLIC keyInfo = session->pubKey;
        TPM2B_ATTEST attest_blob = {};
        TPMT_SIGNATURE signature;
        TPMS_ATTEST attest;        


        int32_t result = decodeAttestationCbor((uint8_t*)req.body.data(),req.body.length(),&attest_blob,&signature);      
        if(result){
            
        }

        TSS2_RC rc = Tss2_MU_TPMS_ATTEST_Unmarshal(
            attest_blob.attestationData,
            attest_blob.size,
            &offset,
            &attest
        );   
        
        if(rc != TSS2_RC_SUCCESS){
            // Couldnt parse the TPMS_ATTEST
            writeLogMessage(ERROR,"Quote was invalid",req.remote_addr,sessionId,session->deviceId);
            return;
        }

        bool quoteIsFresh = false;
        bool signatureMatch = verifyQuoteSignature(keyInfo,attest_blob,signature);

        if(session->lastValidAttestationTimestamp != 0){
            quoteIsFresh = checkQuoteFreshness(session, attest);
        }else{
            writeLogMessage(INFORMATIONAL,"Quote first one received",req.remote_addr,sessionId,session->deviceId);
            quoteIsFresh = true; // The first quote is always considered fresh
        }

        // Is the quote trustworthy ? 
        if (signatureMatch && quoteIsFresh) {          
            writeLogMessage(INFORMATIONAL,"Quote signature matches",req.remote_addr,sessionId,session->deviceId);
            session->lastValidAttestationTimestamp = attest.clockInfo.clock;
            session->isQuoteTrusted = true;
        }
        else{
            writeLogMessage(ATTESTATION_FAILURE,"Quote signature mismatch",req.remote_addr,sessionId,session->deviceId);
            session->isQuoteTrusted = false;
        }
       
        // Quote digest is the same as before
        if((memcmp(session->lastValidAttestation,attest.attested.quote.pcrDigest.buffer, attest.attested.quote.pcrDigest.size) == 0)){
            writeLogMessage(INFORMATIONAL,"Quote digest did not change",req.remote_addr,sessionId,session->deviceId);
            session->isMeasurementsTrusted = true;
        }
        
        session->attestLength = attest.attested.quote.pcrDigest.size;
        memcpy( session->lastValidAttestation,attest.attested.quote.pcrDigest.buffer, attest.attested.quote.pcrDigest.size );
        
        bool trustworthy = checkSessionTrustworthiness(session);
        if(trustworthy){
            writeLogMessage(ATTESTATION_SUCCESS,"Quote valid session TRUSTWORTHY",req.remote_addr,sessionId,session->deviceId);
        }else{
            writeLogMessage(ATTESTATION_FAILURE,"Quote invalid session UNTRUSTWORTHY",req.remote_addr,sessionId,session->deviceId);
        }
        

        
        res.set_content("", "text/plain");
}

void zeroPcrs(uint8_t pcrs[30][EVP_MAX_MD_SIZE]) {
    const uint8_t zeroed[EVP_MAX_MD_SIZE] = {0};
    for(int i = 0; i< 30; i++){
        memmove(pcrs[i],zeroed,EVP_MAX_MD_SIZE);
    }
}


void serverThread() {
    httplib::Server svr;    
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

void enroll(char* ipAddr, char* whitelistPath, char* pcrWhitelistPath) {
    std::cout << "enrolling attester at: " << ipAddr <<std::endl;

}

int main() {
    std::thread server(serverThread);
    bool exit = false;
    while(!exit) {
       
    }

    server.join();    
}