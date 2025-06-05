#include <assert.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <unordered_map>
#include <string>
#include <string.h>
#include "../inc/whitelist.hpp"
#include <fcntl.h>
#include <unistd.h>
#include <iostream>


#define WHITELIST_IGNORE_UNEXPECTED_FILE 1

void readWhitelist( const char* filePath, std::unordered_map<std::string, FileInformation>& whitelist) {
    int fd = open(filePath,O_RDONLY);
    int32_t ret = 1;
    FileInformation fInfo;
    while(ret){
        ret = readBinaryBom(fd,&fInfo);
        std::string key = fInfo.filePath;
        whitelist[key] = fInfo;
        assert((key.length()+1) == fInfo.filePathLength);
    }    
}

/*
Expects a sha256 hash and a FileInformation with SHA256
*/
int32_t checkFilePathWhitelistSha256 (std::string filePath, uint8_t hash[EVP_MAX_MD_SIZE], std::unordered_map<std::string, FileInformation> whitelist) {    
    if (whitelist.find(std::string(filePath)) == whitelist.end()) {
        // File doesnt Exist
        //std::cout << filePath << " doesnt exist in whitelist " << std::endl;
        return WHITELIST_IGNORE_UNEXPECTED_FILE;
    }

    // File should exist
    FileInformation* f = &whitelist[filePath];    
    // Compare hash matches exactly 
    int res = (memcmp(hash,f->fileHash,SHA256_DIGEST_LENGTH) == 0);
    //std::cout << f->filePath << " matches whitelist " << std::endl;
    return res;
}

