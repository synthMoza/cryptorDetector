#ifndef FILE_DB_HEADER
#define FILE_DB_HEADER

#include <sstream>
#include <fstream>

#include "database.h"

namespace sqlite
{

class FileDB : public DataBase
{
    static constexpr const char* m_initDb = R"(
        CREATE TABLE IF NOT EXISTS files(
            path TEXT NOT NULL,
            content TEXT NOT NULL,
            pid INTEGER NOT NULL);
    )";

    static constexpr const char* m_insertSql = "INSERT INTO files( path, content, pid ) VALUES(?, ?, ?);";
    static constexpr const char* m_selectFileByPath = "SELECT * FROM files WHERE path = ?;";
    static constexpr const char* m_ifExists = "SELECT * FROM files WHERE path = ?;";
    static constexpr const char* m_delete = "DELETE FROM files WHERE path = ?";
public:
    FileDB(const char* path) : DataBase(path)
    {
        Exec(m_initDb, nullptr, nullptr);
    }

    bool IsExists(const char* path);
    void DeleteFile(const char* path);
    void AddFile(const char* path, int pid);

    std::string GetFileContent(const char* path);
};

}

#endif // #define FILE_DB_HEADER
