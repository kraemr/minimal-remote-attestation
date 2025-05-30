
#ifndef HTTPLIB_H
#define HTTPLIB_H
    #include "../../common/cpp-httplib/httplib.h"    
#endif

#include <cstddef>
#include <cstdint>
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
#include <iostream>
#include <iomanip>
#include <sstream>
#include <openssl/sha.h>
#include "../inc/log.hpp"
#include "../inc/sessions.hpp"
#include "../inc/whitelist.hpp"
#include "../../common/encoding.h"
#include "../../common/ima_log_lib/inc/ima_verify.h"
#include "../../common/ima_log_lib/inc/ima_template_parser.h"
#include "../../common/ima_log_lib/inc/types.h"
#include "../../common/makecredential.h"

extern void displayDigest(uint8_t *pcr, int32_t n);
extern int32_t  writeEventLog (const char* path, ImaEventSha256* events, uint32_t length);
extern bool verifyQuoteSignature(TPM2B_PUBLIC pub_key, TPM2B_ATTEST quote, TPMT_SIGNATURE signature);
extern int32_t verifyEkCertificate(const char *root_bundle_path, uint8_t* ekCertificate, size_t ekCertLen );
std::map<std::string,ServerSession*> currentSessions;

const char * CERT_BUNDLE_PATH = "../root-certs/root_bundle.pem";

void zeroPcrs(uint8_t pcrs[30][EVP_MAX_MD_SIZE]) {
    const uint8_t zeroed[EVP_MAX_MD_SIZE] = {0};
    for(int i = 0; i< 30; i++){
        memmove(pcrs[i],zeroed,EVP_MAX_MD_SIZE);
    }
}


std::string sha256(uint8_t* data, size_t len) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(data, len, hash);

    std::ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    return oss.str();
}

ServerSession* getSession(std::map<std::string,ServerSession*>& sessionMap, const char* sessionId)
{
    auto it = sessionMap.find(sessionId);
    return (it != sessionMap.end()) ? it->second : nullptr;
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
std::string handleSessionHeaders(const httplib::Request & req) {
    return req.get_header_value("X-Session-Id");
}

bool checkSessionTrustworthiness(ServerSession* sesion) {
    if(sesion == nullptr){
        return false;
    }
    bool trustwothy = sesion->isQuoteTrusted && sesion->isAkTrusted && sesion->isEKTrusted && sesion->isMeasurementsTrusted;
    std::cout << "sesion->isQuoteTrusted" << sesion->isQuoteTrusted << std::endl;
    std::cout << "sesion->isAkTrusted" << sesion->isAkTrusted << std::endl;
    std::cout << "sesion->isEKTrusted" << sesion->isEKTrusted << std::endl;
    std::cout << "sesion->isMeasurementsTrusted" << sesion->isMeasurementsTrusted << std::endl;
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
        success = checkFilePathWhitelistSha256(fileMeasurement.fileName,fileMeasurement.hash,whitelist);
        if (success == false) {
	       session->isMeasurementsTrusted = false;
        }
    }
    return false;
}

void handleIma(std::map<std::string, ServerSession*>& sessionMap,const httplib::Request & req, httplib::Response &res) {    
    std::string sessionId = handleSessionHeaders(req);
    ServerSession* session = getSession(sessionMap,sessionId.data());
    ImaEventSha256* events;
    size_t size = 0;

    if(req.body.empty()){
        res.status = 400;
        return;
    }

    int32_t ret = decodeImaEvents( (uint8_t*)req.body.data(), req.body.size(),&events,&size);    

    if(size == 0) {
        session->isQuoteTrusted = false;  
        session->isMeasurementsTrusted = false;
        res.status = 400;
        return;
    }

    // preemptively set to false, needs to be continuously proven
    session->isMeasurementsTrusted = false;
    session->isQuoteTrusted = false;
    session->waitingForMeasurements = false;

    uint8_t temp[SHA256_DIGEST_LENGTH] = {0};
    
    unsigned int out = 0;
    
    for (int i = 0; i < size; i++) {  
        calculateQuoteStep(&events[i],session->pcrs);                       
        EVP_MD_CTX* mdctx;
        initEvpHashingCtx(&mdctx,CRYPTO_AGILE_SHA256);        
        EVP_DigestUpdate(mdctx, session->pcrs[10] ,SHA256_DIGEST_LENGTH); 
        EVP_DigestFinal_ex(mdctx, temp, &out);
        if (memcmp(session->pcrs[10],session->lastValidAttestation,SHA256_DIGEST_LENGTH) == 0) {
            session->isQuoteTrusted = true;
        }        
        EVP_MD_CTX_free(mdctx);
    }

    session->isMeasurementsTrusted = checkMeasurementsAreWhitelisted(session,events,size);
    free(events);
    res.status = 200;
    res.set_content("", "application/cbor");
}



void handleEnrollChallenge(std::map<std::string, ServerSession*>& sessionMap,const httplib::Request & req, httplib::Response &res) {        
    if(req.body.empty()){
        std::cout << "missing public key" << std::endl;
        return;
    }
    
    uint8_t* ekCert = nullptr;
    size_t ekCertLen = 0;    
    int32_t r = 0;

    TPM2B_PUBLIC pubKey;
    TPMT_SIGNATURE signature;
    TPM2B_ATTEST attest;
    TPM2B_ID_OBJECT credentialBlob;
    TPM2B_ENCRYPTED_SECRET secret;
    ServerSession* session = nullptr;
    
    r = decodePublicKey((uint8_t*)req.body.data(),req.body.length(),&pubKey,&attest,&signature,&ekCert,&ekCertLen);
    if (r != 0){
        writeLogMessage(ERROR,"Attestation Key is invalid",req.remote_addr,"","");
        return;
    }

    r = verifyEkCertificate(CERT_BUNDLE_PATH,ekCert,ekCertLen);
    if(!r) {           
        writeLogMessage(ERROR,"EK Cert is invalid",req.remote_addr,"","");
        return;
    } 
    
    session = new ServerSession();  
    session->enroll_cert_check_success = verifyQuoteSignature(pubKey,attest,signature); 
    if(!session->enroll_cert_check_success){
        std::cout << "verifyQuoteSignature MISMATCH! " << std::endl;      
        session->isEKTrusted = false;
        session->isAkTrusted = false;
        return;      
    }

    session->pubKey = pubKey;
    std::string devId = sha256(ekCert,ekCertLen);
    memcpy(session->deviceId ,devId.c_str(),devId.length());        
    uuid(session->sessionId);                                
    session->deviceId[64] = '\0';                                       
    makeCred(&pubKey,NULL,&credentialBlob,&secret,session->secret); 
    session->secret_len = 18;   

    unsigned char * out_buf;
    size_t size = encode_cred_to_cbor((const unsigned char*)session->sessionId,38,&credentialBlob,&secret,&out_buf);
    const char* s = reinterpret_cast<const char*>(out_buf);    
    res.set_content(s, size, "application/cbor");
    free(out_buf);
    std::pair<char*,ServerSession*> p(session->sessionId,session);  
    sessionMap.insert(p);       
}

void handleEnroll(std::map<std::string, ServerSession*>& sessionMap,const httplib::Request & req, httplib::Response &res) {
        std::string sessionId = handleSessionHeaders(req);
        ServerSession* session = getSession(sessionMap,sessionId.data());          
        if(session != nullptr && memcmp(req.body.c_str(),session->secret,16) == 0 && session->enroll_cert_check_success){
            session->isEKTrusted = true;
            session->isAkTrusted = true;
        }else{
            session->isEKTrusted = false;
            session->isAkTrusted = false;
        }
        res.set_content("", "text/plain");        
}

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

// Checks that the quote is authentic (signed) and fresh
bool checkQuoteAuthentic(ServerSession* session, TPM2B_ATTEST quote_blob,TPMS_ATTEST* quote,TPMT_SIGNATURE sig) {
    bool signatureMatch = verifyQuoteSignature(session->pubKey,quote_blob,sig);
    bool quoteIsFresh = checkQuoteFreshness(session, *quote);
    if (signatureMatch && (quoteIsFresh || session->lastValidAttestationTimestamp == 0 )) {          
        session->lastValidAttestationTimestamp = quote->clockInfo.clock;
        return true;
    }
    else{
        return false;
    }
}

bool quoteDigestChanged(ServerSession* session, TPMS_ATTEST attest) {
    return memcmp(session->lastValidAttestation,attest.attested.quote.pcrDigest.buffer, attest.attested.quote.pcrDigest.size) != 0;
}

void handleQuote(std::map<std::string, ServerSession*>& sessionMap,const httplib::Request & req, httplib::Response &res) {
    auto content = req.body;
    std::string sessionId = handleSessionHeaders(req);
    ServerSession* session = getSession(sessionMap,sessionId.data());
    res.status = 204;
    
    if(session == nullptr ) {
        writeLogMessage(ERROR,"No session",req.remote_addr,sessionId,session->deviceId);
        return;
    }
    if(content.empty()){
        writeLogMessage(ERROR,"Quote was empty",req.remote_addr,sessionId,session->deviceId);
        return;
    }

    size_t offset = 0;
    TPM2B_ATTEST attest_blob;
    TPMT_SIGNATURE signature;
    int32_t result = decodeAttestationCbor((uint8_t*)req.body.data(),req.body.length(),&attest_blob,&signature);      
    
    TPMS_ATTEST attest;
    TSS2_RC rc = Tss2_MU_TPMS_ATTEST_Unmarshal(
        attest_blob.attestationData,
        attest_blob.size,
        &offset,
        &attest
    );

    if(rc != TSS2_RC_SUCCESS){
        // Couldnt parse the TPMS_ATTEST
        writeLogMessage(ERROR,"Quote was invalid",req.remote_addr,sessionId,session->deviceId);
        session->isQuoteTrusted = false;
        return;
    }    
    bool quote_authentic = checkQuoteAuthentic(session,attest_blob,&attest,signature);

    uint8_t expected_pcr[SHA256_DIGEST_LENGTH] = {0};
    unsigned int out = 0;
        
    EVP_MD_CTX* mdctx;
    initEvpHashingCtx(&mdctx,CRYPTO_AGILE_SHA256);
    EVP_DigestUpdate(mdctx, session->pcrs[10] ,SHA256_DIGEST_LENGTH); 
    EVP_DigestFinal_ex(mdctx, expected_pcr, &out);
    EVP_MD_CTX_free(mdctx);

    bool digest_match = memcmp(expected_pcr, attest.attested.quote.pcrDigest.buffer, attest.attested.quote.pcrDigest.size)==0;
    std::cout << quote_authentic << " " << session->waitingForMeasurements << " " << digest_match << std::endl;
    // quote comes in authentic -> set as last valid attestatian and boolean flag waiting_for_measurements = true;
    if(quote_authentic && !session->waitingForMeasurements) {
        memcpy(
            session->lastValidAttestation,
            attest.attested.quote.pcrDigest.buffer, 
            attest.attested.quote.pcrDigest.size 
        );
        session->waitingForMeasurements = !digest_match;
        std::cout << "quote_authentic && !session->waitingForMeasurements" << std::endl;
    }
    // if we have not received measurements, check the digest additionally
    else if(quote_authentic && session->waitingForMeasurements && digest_match ){    
        memcpy(
            session->lastValidAttestation,
            attest.attested.quote.pcrDigest.buffer, 
            attest.attested.quote.pcrDigest.size 
        );     
        std::cout << "quote_authentic && !session->waitingForMeasurements" << std::endl;
    }
    // If the quote is unauthentic, not fresh, or we were waiting for measurements and digest changed
    else{
        session->isQuoteTrusted = false;
        writeLogMessage(ATTESTATION_FAILURE,"Quote invalid session UNTRUSTWORTHY",req.remote_addr,sessionId,session->deviceId);
    }
    res.set_content("", "text/plain");
}


void serverThread() {
    httplib::Server svr;    
    (new Database("sesh.db"))->initFromScript("src/db/init.sql");    

    svr.Post("/measurements", [&](const httplib::Request & req, httplib::Response &res) {       
        handleIma(currentSessions,req,res);
	std::cout << "done" << std::endl;
    });

    // Get the Signing Key from the client
    svr.Post("/enroll", [&](const httplib::Request & req, httplib::Response &res) {      
        handleEnroll(currentSessions, req,res);
    });

    svr.Post("/enroll-challenge", [&](const httplib::Request & req, httplib::Response &res) {      
        handleEnrollChallenge(currentSessions, req,res);
    });

    // Get the quote 
    svr.Post("/attestation", [&](const httplib::Request & req, httplib::Response &res) {
        handleQuote(currentSessions,req,res);
    });
    
    std::cout << "Server is running on port 8084" << std::endl;
    if (!svr.listen("0.0.0.0", 8084)) {
        std::cerr << "Error: server failed to start.\n";
    }
}

int main() {
    std::thread server(serverThread);
    bool exit = false;
    while(!exit) {    
    }

    server.join();    
}
