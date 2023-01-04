#ifndef FILEDB_HEADER
#define FILEDB_HEADER

#include <stdexcept>
#include <string>

#include <sys/stat.h>

#include "sqlite3.h"
#include "error_handling.h"
#include "statement.h"

namespace sqlite
{

class DataBase
{
protected:
    sqlite3* m_db;
public:
    DataBase(const char* path) : m_db(nullptr)
    {
        int err = sqlite3_open(path, &m_db);
        if (err)
        {
            std::string errorString = "Failed to open/create database: ";
            throw std::runtime_error(errorString + sqlite3_errmsg(m_db));
        }

        // restrict access to this database
        err = chmod(path, 0000);
        if (err < 0)
            throw std::runtime_error("Can't restrict access to database");
    }
    
    void Exec(const char* sql, sqlite3_callback callback = nullptr, void* data = nullptr)
    {
        char* errmsg = nullptr;
        CHECK_SQL_MSG(sqlite3_exec(m_db, sql, callback, data, &errmsg), errmsg);
    }

    Statement PrepareV2(const char* sql)
    {
        sqlite3_stmt* stmt = nullptr;
        CHECK_SQL(sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr));
        return Statement(stmt);
    }

    ~DataBase()
    {
        sqlite3_close(m_db);
    }
};

}

#endif // #define FILEDB_HEADER
 