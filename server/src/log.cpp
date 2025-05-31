
#include "../inc/log.hpp"

void writeLogMessage( uint64_t unixTs, LOG_MESSAGE_TYPE msgType, std::string message, std::string ipAddr, std::string deviceId) {
    std::string typeString = ""; 
    std::string seperator = ", ";
    switch(msgType){
        case ERROR:              typeString = "ERROR";break;
        case INFORMATIONAL:      typeString = "INFO";break;
        case ATTESTATION_SUCCESS: typeString = "SUCCESS";break;
        case ATTESTATION_FAILURE: typeString = "FAILURE";break;
    }
    std::cout << unixTs << seperator << ipAddr << seperator << deviceId  << seperator << message << std::endl;
}

