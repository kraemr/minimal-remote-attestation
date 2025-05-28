#include <cstddef>
#include <cstdint>
#include <fcntl.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <unistd.h>
#include <vector>
#include "../../common/ima_log_lib/inc/ima_verify.h"

template <std::size_t BufferSize>
struct ImaEvent {
        uint32_t pcrIndex;
        uint8_t hashOfTemplate[BufferSize];
        uint32_t templateNameLength;
        char templateName[16];
        uint32_t templateDataLength;
        uint8_t* templateData; // contains the hash we actually care about
};
#include <iostream>

int32_t  writeEventLog (int fd, ImaEventSha256* events, uint32_t length) {
    for(uint32_t i = 0; i < length; i++){
        ImaEventSha256 e = events[i];
        size_t bytes = write(fd,&e.pcrIndex,4);
        bytes = write(fd,e.hashOfTemplate,SHA256_DIGEST_LENGTH);
        bytes = write(fd,&e.templateNameLength,4);
        bytes = write(fd,e.templateName,e.templateNameLength);
        bytes = write(fd,&e.templateDataLength,4);
        bytes = write(fd,e.templateData,e.templateDataLength);
    }
    return 0;
} 

int32_t  writeEventLog (const char* path, ImaEventSha256* events, uint32_t length) {
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    for(uint32_t i = 0; i < length; i++){
        ImaEventSha256 e = events[i];
        size_t bytes = write(fd,&e.pcrIndex,4);
        bytes = write(fd,e.hashOfTemplate,SHA256_DIGEST_LENGTH);
        bytes = write(fd,&e.templateNameLength,4);
        bytes = write(fd,e.templateName,e.templateNameLength);
        bytes = write(fd,&e.templateDataLength,4);
        bytes = write(fd,e.templateData,e.templateDataLength);
    }
    close(fd);    
    return 0;
}
