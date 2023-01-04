#ifndef STATEMENT_HEADER
#define STATEMENT_HEADER

#include "sqlite3.h"
#include "error_handling.h"

namespace sqlite
{

class Statement
{
    sqlite3_stmt* m_stmt;
public:
    Statement() : m_stmt (nullptr) {}
    Statement(sqlite3_stmt* stmt) : m_stmt(stmt) {} 

    void Bind(int n, const char* text, sqlite3_destructor_type type = SQLITE_STATIC)
    {
        CHECK_SQL(sqlite3_bind_text(m_stmt, n, text, -1, type));
    }

    void Bind(int n, int data)
    {
        CHECK_SQL(sqlite3_bind_int(m_stmt, n, data));
    }

    // bind blob as container of bytes
    // binds container.data() of container.size() bytes, DOESN'T CHECK FOR SIZE OF UNDERLYING ELEMENT
    template <typename Container>
    void Bind(int n, Container& container, sqlite3_destructor_type type = SQLITE_STATIC)
    {
        CHECK_SQL(sqlite3_bind_blob(m_stmt, n, (void*) container.data(), container.size(), type));
    }

    int Step()
    {
        // TODO: iterate through statement values (when using select, for instance)
        return sqlite3_step(m_stmt);
    }

    const unsigned char* ColumnText(int i)
    {
        return sqlite3_column_text(m_stmt, i);
    }

    int ColumnInt(int i)
    {
        return sqlite3_column_int(m_stmt, i);
    }

    ~Statement()
    {
        if (m_stmt)
            sqlite3_finalize(m_stmt);
    }
};

}

#endif // #define STATEMENT_HEADER
 