#include <iostream>
#include <stdint.h>
#include <sqlite3.h>
#include <fstream>
#include <string>
#include <sstream>

int32_t initSqliteDatabase(const char * scriptPath, const char * dbPath) {
    sqlite3* db = nullptr;
    char* errMsg = nullptr;
    int rc = sqlite3_open(dbPath, &db);
    if (rc != SQLITE_OK) {
        std::cerr << "Can't open database: " << sqlite3_errmsg(db) << std::endl;
        return 1;
    }
    std::ifstream file(scriptPath);
    if (!file) {
        std::cerr << "Failed to open SQL script file." << std::endl;
        sqlite3_close(db);
        return 1;
    }
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string sqlScript = buffer.str();
    rc = sqlite3_exec(db, sqlScript.c_str(), nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        std::cerr << "SQL error: " << (errMsg ? errMsg : "Unknown error") << std::endl;
        if (errMsg) sqlite3_free(errMsg);
        sqlite3_close(db);
        return 1;
    }
    std::cout << "Database initialized successfully." << std::endl;
    sqlite3_close(db);
    return 0;
}