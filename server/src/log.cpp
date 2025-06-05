
#include "../inc/log.hpp"

#include <ctime>

void writeLogMessage(LOG_MESSAGE_TYPE msgType, std::string message, std::string ipAddr,std::string sessionId, std::string deviceId) {
    std::string typeString = ""; 
    std::string seperator = ", ";


    std::time_t t = std::time(nullptr);
    char ISO_8601[100] = {0};
    std::strftime(ISO_8601, sizeof(ISO_8601), "%Y-%m-%dT%H:%M:%S%z", std::localtime(&t));



    switch(msgType){
        case ERROR:              typeString = "ERROR";break;
        case INFORMATIONAL:      typeString = "INFO";break;
        case ATTESTATION_SUCCESS: typeString = "SUCCESS";break;
        case ATTESTATION_FAILURE: typeString = "FAILURE";break;
    }
    
    
    if(deviceId.empty()){
        deviceId = "UNKNOWN_DEVICE";
    }

    std::cout << typeString << seperator  << ISO_8601 << seperator << ipAddr << seperator << sessionId << seperator << deviceId  << seperator << message << std::endl;
}

