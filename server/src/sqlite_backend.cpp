#include "../inc/sessions.hpp"

extern char* uuid(char out[UUID_STR_LEN]);



Database::Database(const std::string& dbPath) {
    if (sqlite3_open(dbPath.c_str(), &db_) != SQLITE_OK) {
        throw std::runtime_error("Can't open database: " + std::string(sqlite3_errmsg(db_)));
    }
}

Database::~Database() {
    if (db_) {
        sqlite3_close(db_);
    }
}

bool Database::initFromScript(const std::string& scriptPath) {
    std::ifstream file(scriptPath);
    if (!file) {
        std::cerr << "Failed to open SQL script file.\n";
        return false;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string sqlScript = buffer.str();

    char* errMsg = nullptr;
    int rc = sqlite3_exec(db_, sqlScript.c_str(), nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        std::cerr << "SQL error: " << (errMsg ? errMsg : "Unknown error") << "\n";
        sqlite3_free(errMsg);
        return false;
    }
    std::cout << "Database initialized successfully.\n";
    return true;
}

bool Database::loadServerSession(const char* deviceId, const char* sessionId, ServerSession* session) {
    const char* sql = "SELECT session_id, public_key, quote, last_quote_index "
                      "FROM RemoteAttestationSession WHERE device_id = ? AND session_id = ?";
    sqlite3_stmt* stmt = nullptr;

    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_text(stmt, 1, deviceId, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, sessionId, -1, SQLITE_STATIC);

    bool result = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        strncpy(session->deviceId, deviceId, DEV_ID_LENGTH);
        strncpy(session->sessionId, (const char*)sqlite3_column_text(stmt, 0), SESSION_ID_MAX_LENGTH);

        // Public key
        int len = sqlite3_column_bytes(stmt, 1);
        const void* data = sqlite3_column_blob(stmt, 1);
        //session->pubKey = (uint8_t*)malloc(len);
        //memcpy(session->pubKey, data, len);
        //session->pubKeyLength = len;

        // Quote
        int quoteLen = sqlite3_column_bytes(stmt, 2);
        const void* quoteData = sqlite3_column_blob(stmt, 2);
        if (quoteLen > 0) {
            memcpy(session->lastValidAttestation, quoteData, quoteLen);
        }
        session->attestLength = quoteLen;
        session->lastValidAtestationImaIndex = sqlite3_column_int64(stmt, 3);
        result = true;
    }

    sqlite3_finalize(stmt);
    return result;
}

bool Database::updateServerSession(const ServerSession* session) {
    const char* sql = "UPDATE RemoteAttestationSession SET "
                      "public_key = ?, quote = ?, last_quote_index = ? "
                      "WHERE device_id = ? AND session_id = ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;

    //sqlite3_bind_blob(stmt, 1, session->pubKey, session->pubKeyLength, SQLITE_STATIC);
    if (session->attestLength > 0) {
        sqlite3_bind_blob(stmt, 2, session->lastValidAttestation, session->attestLength, SQLITE_STATIC);
    } else {
        sqlite3_bind_null(stmt, 2);
    }
    sqlite3_bind_int64(stmt, 3, session->lastValidAtestationImaIndex);
    sqlite3_bind_int64(stmt, 4, 1); // You may want to pass `deviceId` instead
    sqlite3_bind_text(stmt, 5, session->sessionId, -1, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE);
}

bool Database::addSession(ServerSession* session) {
    const char* sql = R"(
        INSERT INTO RemoteAttestationSession (
            device_id, session_id, path_to_log_directory,
            quote, public_key, last_quote_index
        ) VALUES (?, ?, ?, ?, ?, ?);
    )";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;

    sqlite3_bind_int(stmt, 1, 1);  // Static device ID, adjust if needed
    sqlite3_bind_text(stmt, 2, session->sessionId, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, "/logs/device42/", -1, SQLITE_STATIC);
    sqlite3_bind_null(stmt, 4);
    //sqlite3_bind_blob(stmt, 5, session->pubKey, session->pubKeyLength, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 6, 0);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

/*
Should take the deviceId Hash
*/
bool Database::addNewDevice() {
    char uuidStr[UUID_STR_LEN] = {0};
    uuid(uuidStr); // assuming `uuid()` fills buffer with UUID string

    const char* sql = "INSERT INTO DeviceIds(device_id) VALUES(?)";
    sqlite3_stmt* stmt = nullptr;

    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;
    sqlite3_bind_text(stmt, 1, uuidStr, -1, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

