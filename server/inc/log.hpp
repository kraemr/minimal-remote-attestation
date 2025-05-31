


enum LOG_MESSAGE_TYPE {
    ERROR,
    INFORMATIONAL,
    ATTESTATION_SUCCESS,
    ATTESTATION_FAILURE,
};

#include <string>
#include <iostream>



void writeLogMessage( uint64_t unixTs, LOG_MESSAGE_TYPE msgType, std::string message, std::string ipAddr, std::string deviceId);