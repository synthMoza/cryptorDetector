#include <sqlite/filedb.h>

#include <iostream>
#include <fstream>
#include <vector>

using namespace sqlite;

void FileDB::DeleteFile(const char* path)
{
    auto stmt = PrepareV2(m_delete);
    stmt.Bind(1, path);
    stmt.Step();
}

void FileDB::AddFile(const char* path, int pid)
{
    // delete previous file content, if exists
    DeleteFile(path);

    // read file as blob
    std::ifstream inputFile(path, std::ios::binary);
    std::vector<unsigned char> buffer(std::istreambuf_iterator<char>(inputFile), {});

    // prepare cmd
    // table columns: 'path', 'content', 'pid'
    auto stmt = PrepareV2(m_insertSql);
    
    stmt.Bind(1, path);
    stmt.Bind(2, buffer);
    stmt.Bind(3, pid);
    
    stmt.Step();
}

bool FileDB::IsExists(const char* path)
{
    auto stmt = PrepareV2(m_ifExists);
    stmt.Bind(1, path);
    
    return (stmt.Step() == SQLITE_ROW);
}

std::string FileDB::GetFileContent(const char* path)
{
    std::string fileContent;

    auto stmt = PrepareV2(m_selectFileByPath);
    stmt.Bind(1, path);

    int res = 0;
    while ((res = stmt.Step()) == SQLITE_ROW)
    {
        for (int i = 0; i < res; ++i)
            std::cout << stmt.ColumnText(i) << std::endl;
    }

    if (res != SQLITE_DONE)
        CHECK_SQL(res);
    
    return fileContent;
}
