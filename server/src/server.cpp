#ifndef HTTPLIB_H
#define HTTPLIB_H
    #include "../../common/cpp-httplib/httplib.h"
    #include <exception>
    #include <openssl/evp.h>
    #include <openssl/sha.h>
    #include <stdint.h>
    #include <tss2/tss2_common.h>
    #include <tss2/tss2_tpm2_types.h>
#endif

#include "../../common/encoding.h"
#include "../inc/sessions.hpp"
#include "../../common/ima_log_lib/inc/ima_verify.h"
#include "../../common/ima_log_lib/inc/types.h"

extern void displayDigest(uint8_t *pcr, int32_t n);

int main() {
    httplib::Server svr;
    const uint8_t zeroed[EVP_MAX_MD_SIZE] = {0};
    uint8_t pcrs[30][EVP_MAX_MD_SIZE];
    uint32_t f = 0;
    for(int i = 0; i< 30; i++){
        memmove(pcrs[i],zeroed,EVP_MAX_MD_SIZE);
    }


    svr.Post("/ima", [&](const httplib::Request & req, httplib::Response &res) {
        displayDigest(pcrs[10],SHA256_DIGEST_LENGTH);
        auto content = req.body;        
        if(content.empty()){
            std::cout << "got no events ?" << std::endl;
            return;
        }
        // Probably would be better to keep a static buffer, that is same size as client, so no memory allocs are actually needed
        struct ImaEventSha256* events = NULL;
        size_t size = 0;
        int32_t t = decodeImaEvents( (uint8_t*)content.data(), content.size(),&events,&size);
        calculateQuote(events,size,pcrs, CRYPTO_AGILE_SHA256);
        displayDigest(pcrs[10],SHA256_DIGEST_LENGTH);

        std::string sessionId = req.get_header_value("Session-ID");
        res.set_content("", "application/cbor");
    });

    // Get the Signing Key from the client
    svr.Post("/enroll", [&](const httplib::Request & req, httplib::Response &res) {        
        char out[UUID_STR_LEN];
        TPM2B_PUBLIC pubKey;
        auto content = req.body;

        if(content.empty()){
            std::cout << "missing keys" << std::endl;
            return;
        }

        try{
            uuid(out);
            decodePublicKey((uint8_t*)req.body.data(), req.body.length(), &pubKey);
            std::cout << pubKey.size << std::endl;
        }
        catch(std::exception e){
            std::cout << e.what() << std::endl;
        }
        res.set_content(out, "text/plain");        
    });

    // Get the quote 
    svr.Post("/quote", [&](const httplib::Request & req, httplib::Response &res) {
        auto content = req.body;
        if(content.empty()){
            std::cout << "missing keys" << std::endl;
            return;
        }

        std::cout<< "/quote: " << content.size() << std::endl;



        std::string sessionId = req.get_header_value("Session-ID");

        res.set_content("", "application/cbor");
    });
    
    std::cout << "Server is running on port 8084" << std::endl;
    if (!svr.listen("0.0.0.0", 8084)) {
        std::cerr << "Error: server failed to start.\n";
    }
}