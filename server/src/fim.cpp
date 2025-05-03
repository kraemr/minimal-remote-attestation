#include <cstdint>
#include <openssl/evp.h>
#include <sqlite3.h>
#include <stdint.h>
#include <vector>

typedef struct Measurement {
    uint8_t hash[EVP_MAX_MD_SIZE];
    const char* fileName;
    uint64_t timeStamp;
}Measurement;

typedef struct MeasurementSession {
    std::vector<uint8_t> deviceId;
    std::vector<uint8_t> sessionId;
    std::vector<Measurement> measurements;
}MeasurementSession;

typedef struct MeasurementsDeviceId {
    std::vector<uint8_t> devId;
    std::vector<MeasurementSession> sessions;
}MeasurementsDeviceId;

// add a Measurement to a session of a DevId
// on success return > 0
// on failure return 0 or lower
int32_t addMeasurement(std::vector<uint8_t> devId,std::vector<uint8_t> sessionId, Measurement measurement){
    return 1;
}


int32_t getMeasurementsBySession(std::vector<uint8_t> sessionId, std::vector<Measurement>& measurements) {
    return 1;
}

int32_t getAllMeasurementsByDevice(std::vector<uint8_t> sessionId, std::vector<Measurement>& measurements) {
    // retrieve all sessions
    // join them
    // and return them
}