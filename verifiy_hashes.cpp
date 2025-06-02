


/*

*/

#include <assert.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <unordered_map>
#include <string>
#include <string.h>
#include "common/software-bom/inc/software_bom.h"
#include <fcntl.h>
#include <unistd.h>
#include <iostream>

// TODO: 
/*
Read the entire bom into a std::unordered_map where filepath is key
readBom
*/


void readWhitelist( const char* filePath, std::unordered_map<std::string, FileInformation>& whitelist) {
    int fd = open(filePath,O_RDONLY);
    int32_t ret = 1;
    FileInformation fInfo;
    while(ret){
        ret = readBinaryBom(fd,&fInfo);
        std::string key = fInfo.filePath;
        whitelist[key] = fInfo;
        //std::cout << key << " length" << key.length() << " should be " << fInfo.filePathLength  << std::endl;
        assert(key.length() == fInfo.filePathLength);
    }    
}

/*
Expects a sha256 hash and a FileInformation with SHA256

*/
int32_t checkFilePathWhitelistSha256 (std::string filePath, uint8_t hash[EVP_MAX_MD_SIZE], std::unordered_map<std::string, FileInformation> whitelist) {
    
    // Check if file exists in whitelist or not
    // IF a file doesnt exist return failure
    FileInformation f = whitelist[filePath];    
    return (memcmp(hash,f.fileHash,SHA256_DIGEST_LENGTH) == 0);
}

int main(){
    std::unordered_map<std::string, FileInformation> whitelist;
    readWhitelist("test",whitelist);
    //checkFilePathWhitelistSha256("/bin/x86_64-w64-mingw32-gcc");
}