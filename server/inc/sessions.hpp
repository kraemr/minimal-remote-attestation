#include <uuid/uuid.h>
extern char* uuid(char out[UUID_STR_LEN]);

#ifndef DATABASE_HPP
#define DATABASE_HPP
#include <string>
#include <string.h>
#include <sqlite3.h>
#include "../../common/common-types.h"
#include <iostream>
#include <fstream>
#include <sstream>

class Database {
public:
    Database(const std::string& dbPath);
    ~Database();
    bool initFromScript(const std::string& scriptPath);
    bool loadServerSession(const char* deviceId, const char* sessionId, ServerSession* session);
    bool updateServerSession(const ServerSession* session);
    bool addSession(ServerSession* session);
    bool addNewDevice();
private:
    sqlite3* db_;
};

#endif // DATABASE_HPP
