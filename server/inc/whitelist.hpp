

#include <unordered_map>
#include <string>
#include "../../common/software-bom/inc/software_bom.h"

extern void readWhitelist( const char* filePath, std::unordered_map<std::string, FileInformation>& whitelist);
int32_t checkFilePathWhitelistSha256 (std::string filePath, uint8_t hash[EVP_MAX_MD_SIZE], std::unordered_map<std::string, FileInformation> whitelist);